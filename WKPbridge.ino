// WKPbridge.ino
// ESP32-C3 BLE-to-WiFi bridge for Wyze Wireless Keypad (WLCKKP1)
//
// Fix log:
//  r1-r9: scan/connect/decompile (see git history)
//  r10:  Flip to PERIPHERAL mode -- keypad is the BLE central.
//  r10a: Fix compile.
//  r10b: MAC byte order fix; tryLockMac; BT coex; tighter adv interval.
//  r10c: Advertise FE50 UUID; log all adv UUIDs from scanned devices.
//  r10d: SCAN RESULT -- real lock (E2:79:A5:DC:36:4D) adv contains:
//          Service UUID: ONLY 0x180F (Battery Service)
//          NO FE50, NO NUS in adv packet.
//        FIX: Match real lock adv exactly:
//          - Adv packet: name="Wyze Lock", svc=0x180F only, mfr=59 44 <MAC> 00 02 0A
//          - NUS (6e400001/02/03) stays in GATT server only (keypad discovers post-connect).
//        Added /api/advMode to toggle 180F-only vs 180F+FE50 at runtime.

#define DEBUG_SERIAL 1

#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <ESPmDNS.h>
#include <ArduinoOTA.h>
#include <Preferences.h>
#include <NimBLEDevice.h>
#include <esp_coexist.h>
#include <vector>

#include "mbedtls/aes.h"
#include <Secrets.h>
#include "html.h"

static const char *HOSTNAME = "WKPbridge";
static const char *AP_SSID  = "WKPbridge-setup";
static const byte DNS_PORT  = 53;

static const char *NUS_SERVICE_UUID = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
static const char *NUS_RX_UUID      = "6e400002-b5a3-f393-e0a9-e50e24dcca9e";
static const char *NUS_TX_UUID      = "6e400003-b5a3-f393-e0a9-e50e24dcca9e";

static const uint16_t WYZE_COMPANY_ID = 0x4459;
static const char * const WYZE_ADV_NAMES[] = {
  "Wyze Lock", "DingDing", "KP-01", "DD-Fact", nullptr
};

static const uint8_t AES_KEY[16] = {
  0xD3, 0x7F, 0xCD, 0x69, 0x03, 0xFE, 0x6E, 0x69,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t REAL_LOCK_MAC[6] = {0xE2, 0x79, 0xA5, 0xDC, 0x36, 0x4D};

// ---- Peripheral state ----
static NimBLEServer         *bleServer  = nullptr;
static NimBLEService        *nusService = nullptr;
static NimBLECharacteristic *rxChr      = nullptr;
static NimBLECharacteristic *txChr      = nullptr;
static bool          gAdvConnected  = false;
static uint32_t      gConnHandle    = 0xFFFF;
static unsigned long gConnectedAtMs = 0;
static String        gAdvPeer       = "";
static bool          gUseLockMac    = false;
// advMode: 0=exact (180F only, default), 1=plus (180F+FE50)
static int           gAdvMode       = 0;

static uint8_t  gLastNonce[8] = {0};
static bool     gNonceReceived = false;

NimBLEClient               *bleClient = nullptr;
NimBLERemoteCharacteristic *writeChr  = nullptr;
NimBLERemoteCharacteristic *notifyChr = nullptr;

#if DEBUG_SERIAL
  #define DBG_BEGIN(x)   Serial.begin(x)
  #define DBG_PRINTLN(x) Serial.println(x)
#else
  #define DBG_BEGIN(x)
  #define DBG_PRINTLN(x)
#endif

struct Settings {
  String  wifiSsid, wifiPsk, bleAddress, bleAddrType, bleName;
  String  serviceUuid, writeUuid, notifyUuid;
  bool    autoConnect = false, writeWithResponse = false;
  uint8_t scanSeconds = 5;
  String  mqttHost, mqttUser, mqttPass, mqttTopic;
  uint16_t mqttPort = 1883;
};

Preferences prefs;
WebServer   server(80);
DNSServer   dns;
Settings    settings;

bool portalMode=false, wifiWasConnected=false, otaReady=false, mdnsReady=false, scanRunning=false;
unsigned long lastWifiTryMs=0, lastStateMs=0;
String logBuffer, lastScanJson="[]", lastTxHex, lastRxHex;

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------
String jsonEscape(const String &in){
  String out; out.reserve(in.length()+16);
  for(size_t i=0;i<in.length();i++){
    char c=in[i]; switch(c){
      case '\\': out+="\\\\"; break; case '"': out+="\\\""; break;
      case '\n': out+="\\n";  break; case '\r': break;
      case '\t': out+="\\t";  break;
      default: if((uint8_t)c<32)out+=' '; else out+=c;
    }
  }
  return out;
}
void addLog(const String &line){
  String s=String(millis())+" | "+line; logBuffer+=s+"\n";
  if(logBuffer.length()>32000)logBuffer.remove(0,logBuffer.length()-32000);
  DBG_PRINTLN(s);
}
String bytesToHex(const uint8_t *d,size_t l){
  const char *h="0123456789ABCDEF"; String o; o.reserve(l*3);
  for(size_t i=0;i<l;i++){o+=h[(d[i]>>4)&0xF];o+=h[d[i]&0xF];if(i+1<l)o+=' ';} return o;
}
bool parseHexString(String s,std::vector<uint8_t>&out){
  out.clear();s.replace("0x","");s.replace("0X","");s.replace(",","");s.replace(":"," ");s.replace("-"," ");
  while(s.indexOf("  ")>=0)s.replace("  "," ");s.trim();if(s.isEmpty())return false;
  int st=0;
  while(st<(int)s.length()){
    while(st<(int)s.length()&&s[st]==' ')st++;
    if(st>=(int)s.length())break;
    int e=s.indexOf(' ',st);if(e<0)e=s.length();
    String t=s.substring(st,e);t.trim();if(t.isEmpty()){st=e+1;continue;}
    if(t.length()>2)return false;
    char *ep=nullptr;long v=strtol(t.c_str(),&ep,16);
    if(!ep||*ep!=0||v<0||v>255)return false;
    out.push_back((uint8_t)v);st=e+1;
  }
  return !out.empty();
}

// --------------------------------------------------------------------------
// Settings
// --------------------------------------------------------------------------
void loadSettings(){
  prefs.begin("wkpbridge",true);
  settings.wifiSsid    =prefs.getString("wifi_ssid",MYSSID);
  settings.wifiPsk     =prefs.getString("wifi_psk", MYPSK);
  settings.bleAddress  =prefs.getString("ble_addr", "");
  settings.bleAddrType =prefs.getString("ble_atype","random");
  settings.bleName     =prefs.getString("ble_name", "KP-01");
  settings.serviceUuid =prefs.getString("svc_uuid", NUS_SERVICE_UUID);
  settings.writeUuid   =prefs.getString("wr_uuid",  NUS_RX_UUID);
  settings.notifyUuid  =prefs.getString("nt_uuid",  NUS_TX_UUID);
  settings.autoConnect      =prefs.getBool ("auto_conn",false);
  settings.writeWithResponse=prefs.getBool ("wr_rsp",  false);
  settings.scanSeconds      =prefs.getUChar("scan_sec",5);
  settings.mqttHost =prefs.getString("mqtt_host",""); settings.mqttPort=prefs.getUShort("mqtt_port",1883);
  settings.mqttUser =prefs.getString("mqtt_user",""); settings.mqttPass=prefs.getString("mqtt_pass","");
  settings.mqttTopic=prefs.getString("mqtt_topic","wkpbridge");
  prefs.end();
  if(settings.serviceUuid=="0000fe50-0000-1000-8000-00805f9b34fb"){
    settings.serviceUuid=NUS_SERVICE_UUID;
    settings.writeUuid  =NUS_RX_UUID;
    settings.notifyUuid =NUS_TX_UUID;
    addLog("migrate: UUIDs -> NUS");
  }
}
void saveSettings(){
  prefs.begin("wkpbridge",false);
  prefs.putString("wifi_ssid",settings.wifiSsid); prefs.putString("wifi_psk", settings.wifiPsk);
  prefs.putString("ble_addr", settings.bleAddress);prefs.putString("ble_atype",settings.bleAddrType);
  prefs.putString("ble_name", settings.bleName);  prefs.putString("svc_uuid", settings.serviceUuid);
  prefs.putString("wr_uuid",  settings.writeUuid); prefs.putString("nt_uuid",  settings.notifyUuid);
  prefs.putBool("auto_conn",settings.autoConnect); prefs.putBool("wr_rsp",settings.writeWithResponse);
  prefs.putUChar("scan_sec",settings.scanSeconds);
  prefs.putString("mqtt_host",settings.mqttHost); prefs.putUShort("mqtt_port",settings.mqttPort);
  prefs.putString("mqtt_user",settings.mqttUser); prefs.putString("mqtt_pass",settings.mqttPass);
  prefs.putString("mqtt_topic",settings.mqttTopic);
  prefs.end(); addLog("Settings saved");
}

// --------------------------------------------------------------------------
// WiFi
// --------------------------------------------------------------------------
void startPortal(){if(portalMode)return;WiFi.mode(WIFI_AP_STA);WiFi.softAP(AP_SSID);dns.start(DNS_PORT,"*",WiFi.softAPIP());portalMode=true;addLog("Portal: "+String(AP_SSID)+" "+WiFi.softAPIP().toString());}
void stopPortal(){if(!portalMode)return;dns.stop();WiFi.softAPdisconnect(true);portalMode=false;addLog("Portal stopped");}
void beginWiFi(bool keepAp){
  WiFi.persistent(false);WiFi.setAutoReconnect(true);
  WiFi.mode(keepAp?WIFI_AP_STA:WIFI_STA);WiFi.setHostname(HOSTNAME);
  if(settings.wifiSsid.isEmpty())settings.wifiSsid=MYSSID;
  if(settings.wifiPsk.isEmpty()) settings.wifiPsk =MYPSK;
  addLog("WiFi SSID="+settings.wifiSsid);
  WiFi.begin(settings.wifiSsid.c_str(),settings.wifiPsk.c_str());
  WiFi.setTxPower(WIFI_POWER_15dBm); lastWifiTryMs=millis();
}
void ensureMDNSOTA(){
  if(WiFi.status()!=WL_CONNECTED)return;
  if(!mdnsReady){if(MDNS.begin(HOSTNAME)){MDNS.addService("http","tcp",80);mdnsReady=true;addLog("mDNS: http://"+String(HOSTNAME)+".local/");}else addLog("mDNS failed");}
  if(!otaReady){ArduinoOTA.setHostname(HOSTNAME);ArduinoOTA.onStart([](){addLog("OTA start");});ArduinoOTA.onEnd([](){addLog("OTA end");});ArduinoOTA.onError([](ota_error_t e){addLog("OTA err "+String((int)e));});ArduinoOTA.begin();otaReady=true;addLog("OTA ready");}
}
void mqttPublish(const String &p){if(settings.mqttHost.isEmpty())return;addLog("MQTT: "+p);}
void serviceMQTT(){}

// --------------------------------------------------------------------------
// AES-ECB
// --------------------------------------------------------------------------
bool computeAuthResponse(const uint8_t *nonce8, uint8_t *resp8){
  uint8_t block[16]={0}; memcpy(block,nonce8,8);
  mbedtls_aes_context aes; mbedtls_aes_init(&aes);
  if(mbedtls_aes_setkey_enc(&aes,AES_KEY,128)!=0){mbedtls_aes_free(&aes);return false;}
  uint8_t out[16]={0};
  bool ok=(mbedtls_aes_crypt_ecb(&aes,MBEDTLS_AES_ENCRYPT,block,out)==0);
  mbedtls_aes_free(&aes);
  if(ok)memcpy(resp8,out,8);
  return ok;
}

// --------------------------------------------------------------------------
// TX notify
// --------------------------------------------------------------------------
bool sendNotify(const uint8_t *d,size_t l,const char *tag){
  if(!gAdvConnected||!txChr){addLog(String("TX NOTIFY failed: not connected - ")+tag);return false;}
  lastTxHex=bytesToHex(d,l);
  addLog(String("TX NOTIFY ")+tag+": "+lastTxHex);
  bool ok=txChr->notify(d,l);
  addLog(String("TX result: ")+(ok?"OK":"FAIL"));
  return ok;
}

// --------------------------------------------------------------------------
// Decode RX
// --------------------------------------------------------------------------
void decodeRxPacket(const uint8_t *d,size_t l){
  addLog("  RAW["+String(l)+"]: "+bytesToHex(d,l));
  if(l>=5&&d[0]==0xDE&&d[1]==0xC0&&d[2]==0xAD&&d[3]==0xDE){
    uint8_t op=d[4]; String opName;
    switch(op){case 0x00:opName="UNLOCK";break;case 0x01:opName="BIND";break;
               case 0x02:opName="KEYPRESS";break;case 0xFE:opName="PROBE_FE";break;
               case 0xFF:opName="GET_RANDOM";break;default:opName="OP_0x"+String(op,HEX);}
    String payload=(l>5)?bytesToHex(d+5,l-5):"(none)";
    addLog("  -> dd_proto op="+opName+" payload="+payload);
    mqttPublish(bytesToHex(d,l)); return;
  }
  if(l==8){
    addLog("  -> 8-byte nonce challenge");
    memcpy(gLastNonce,d,8); gNonceReceived=true;
    uint8_t resp[8]={0};
    if(computeAuthResponse(gLastNonce,resp)){
      addLog("  -> AES resp: "+bytesToHex(resp,8));
      delay(20); bool ok=sendNotify(resp,8,"AUTH_RESP");
      addLog(ok?"  -> Auth OK":"  -> Auth FAILED");
    } else addLog("  -> AES FAILED");
    mqttPublish(bytesToHex(d,l)); return;
  }
  addLog("  -> Unknown len="+String(l));
  mqttPublish(bytesToHex(d,l));
}

// --------------------------------------------------------------------------
// BLE Server callbacks
// --------------------------------------------------------------------------
class ServerCB : public NimBLEServerCallbacks {
public:
  void onConnect(NimBLEServer*,NimBLEConnInfo &info) override {
    gAdvConnected=true; gConnHandle=info.getConnHandle();
    gConnectedAtMs=millis(); gAdvPeer=String(info.getAddress().toString().c_str());
    addLog(">>> CONNECT peer="+gAdvPeer+" handle="+String(gConnHandle)+" t="+String(gConnectedAtMs)+"ms");
    addLog("    itvl="+String(info.getConnInterval())+" lat="+String(info.getConnLatency())+" tmo="+String(info.getConnTimeout())+" mtu="+String(info.getMTU()));
    NimBLEDevice::getAdvertising()->stop();
    addLog("    Adv stopped. Waiting for subscribe+write...");
  }
  void onDisconnect(NimBLEServer*,NimBLEConnInfo &info,int reason) override {
    unsigned long dur=gConnectedAtMs?(millis()-gConnectedAtMs):0;
    addLog(">>> DISCONNECT peer="+String(info.getAddress().toString().c_str())
           +" reason=0x"+String(reason,HEX)+" HCI=0x"+String(reason&0xFF,HEX)
           +" dur="+String(dur)+"ms nonceRx="+String(gNonceReceived?"YES":"NO"));
    gAdvConnected=false; gConnHandle=0xFFFF; gConnectedAtMs=0; gAdvPeer=""; gNonceReceived=false;
    NimBLEDevice::getAdvertising()->start();
    addLog("    Adv restarted");
  }
  void onAuthenticationComplete(NimBLEConnInfo &info) override {
    addLog(">>> AUTH enc="+String(info.isEncrypted())+" bonded="+String(info.isBonded()));
  }
  void onMTUChange(uint16_t mtu,NimBLEConnInfo&) override {
    addLog(">>> MTU="+String(mtu));
  }
};
ServerCB gServerCB;

class RxCharCB : public NimBLECharacteristicCallbacks {
public:
  void onWrite(NimBLECharacteristic *chr,NimBLEConnInfo &info) override {
    std::string val=chr->getValue(); size_t l=val.size();
    const uint8_t *d=(const uint8_t*)val.data();
    lastRxHex=bytesToHex(d,l);
    unsigned long t=gConnectedAtMs?(millis()-gConnectedAtMs):0;
    addLog("RX len="+String(l)+" t+"+String(t)+"ms from="+String(info.getAddress().toString().c_str()));
    decodeRxPacket(d,l);
  }
  void onSubscribe(NimBLECharacteristic*,NimBLEConnInfo &info,uint16_t sub) override {
    unsigned long t=gConnectedAtMs?(millis()-gConnectedAtMs):0;
    addLog(">>> SUBSCRIBE val=0x"+String(sub,HEX)+" t+"+String(t)+"ms peer="+String(info.getAddress().toString().c_str()));
    if(sub==1) addLog("    Subscribed to notify -- waiting for nonce write...");
    else if(sub==0) addLog("    UNSUBSCRIBED");
  }
};
RxCharCB gRxCharCB;

// --------------------------------------------------------------------------
// Build mfr data (MAC MSB-first in packet)
// --------------------------------------------------------------------------
void buildMfrData(uint8_t *out11,const uint8_t *mac6_msb){
  out11[0]=0x59;out11[1]=0x44;
  for(int i=0;i<6;i++)out11[2+i]=mac6_msb[i];
  out11[8]=0x00;out11[9]=0x02;out11[10]=0x0A;
}

// --------------------------------------------------------------------------
// Advertising -- r10d: 0x180F ONLY in adv (matches real lock exactly)
// --------------------------------------------------------------------------
void startAdvertising(){
  NimBLEAdvertising *adv=NimBLEDevice::getAdvertising();
  adv->reset();

  adv->addServiceUUID("180f"); // Battery -- only UUID real lock puts in adv
  if(gAdvMode==1){
    adv->addServiceUUID("fe50");
    addLog("Adv mode 1: 180F+FE50");
  } else {
    addLog("Adv mode 0: 180F only (real lock match)");
  }
  adv->setName("Wyze Lock");

  uint8_t mfrData[11];
  if(gUseLockMac){
    buildMfrData(mfrData,REAL_LOCK_MAC);
    addLog("Adv MAC: REAL LOCK "+bytesToHex(REAL_LOCK_MAC,6));
  } else {
    NimBLEAddress own=NimBLEDevice::getAddress();
    const uint8_t *v=own.getBase()->val;
    uint8_t msb[6]={v[5],v[4],v[3],v[2],v[1],v[0]};
    buildMfrData(mfrData,msb);
    addLog("Adv MAC: OWN "+bytesToHex(msb,6));
  }
  adv->setManufacturerData(std::string((char*)mfrData,11));
  adv->setMinInterval(32); adv->setMaxInterval(32);

  bool ok=adv->start();
  addLog("Adv "+String(ok?"OK":"FAIL")+" mfr="+bytesToHex(mfrData,11));
  addLog("  addr="+String(NimBLEDevice::getAddress().toString().c_str()));
}
void stopAdvertising(){NimBLEDevice::getAdvertising()->stop();addLog("Adv stopped");}

// --------------------------------------------------------------------------
// BLE peripheral setup
// --------------------------------------------------------------------------
void setupBlePeripheral(){
  addLog("r10d: BLE peripheral setup");
  NimBLEDevice::setSecurityAuth(0);
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_NO_INPUT_OUTPUT);

  bleServer=NimBLEDevice::createServer();
  bleServer->setCallbacks(&gServerCB);

  nusService=bleServer->createService(NUS_SERVICE_UUID);
  rxChr=nusService->createCharacteristic(NUS_RX_UUID,NIMBLE_PROPERTY::WRITE|NIMBLE_PROPERTY::WRITE_NR);
  rxChr->setCallbacks(&gRxCharCB);
  txChr=nusService->createCharacteristic(NUS_TX_UUID,NIMBLE_PROPERTY::NOTIFY);
  txChr->setCallbacks(&gRxCharCB);
  nusService->start();
  addLog("  GATT NUS (not in adv): RX="+String(NUS_RX_UUID));

  esp_coex_preference_set(ESP_COEX_PREFER_BT);
  addLog("  Coex: BT priority");
  startAdvertising();
}

// --------------------------------------------------------------------------
// Scan
// --------------------------------------------------------------------------
bool isWyzeDevice(const NimBLEAdvertisedDevice *dev){
  if(dev->haveManufacturerData()){const std::string &m=dev->getManufacturerData();if(m.size()>=2&&(((uint8_t)m[0]|((uint8_t)m[1]<<8))==WYZE_COMPANY_ID))return true;}
  if(dev->haveName()){std::string n=dev->getName();for(int i=0;WYZE_ADV_NAMES[i];i++)if(n==WYZE_ADV_NAMES[i])return true;}
  return false;
}
void logDeviceDetail(const NimBLEAdvertisedDevice *dev){
  if(dev->haveManufacturerData()){
    const std::string &m=dev->getManufacturerData(); size_t len=m.size();
    String hex; for(size_t i=0;i<len;i++){const char*h="0123456789ABCDEF";hex+=h[((uint8_t)m[i]>>4)&0xF];hex+=h[(uint8_t)m[i]&0xF];if(i+1<len)hex+=' ';}
    addLog("    mfr("+String(len)+"b): "+hex);
    if(len>=8){char ms[18];snprintf(ms,sizeof(ms),"%02X:%02X:%02X:%02X:%02X:%02X",(uint8_t)m[2],(uint8_t)m[3],(uint8_t)m[4],(uint8_t)m[5],(uint8_t)m[6],(uint8_t)m[7]);addLog("    mfrMAC: "+String(ms));}
    if(len>10){uint8_t dt=(uint8_t)m[10];addLog("    devType=0x"+String(dt,HEX)+(dt==0x07?" KP-01":(dt==0x0A?" Wyze Lock":""))); }
  }
  int sc=dev->getServiceUUIDCount();
  if(sc>0){addLog("    advUUIDs("+String(sc)+"):");for(int i=0;i<sc;i++){NimBLEUUID u=dev->getServiceUUID(i);addLog("      "+String(u.toString().c_str()));}}
  else addLog("    No adv UUIDs");
  if(dev->haveTXPower())addLog("    txPwr="+String(dev->getTXPower())+"dBm");
}

String scanJson(){
  if(gAdvConnected){addLog("Scan skipped: connected");return lastScanJson;}
  if(scanRunning){addLog("Scan busy");return lastScanJson;}
  scanRunning=true;
  NimBLEDevice::getAdvertising()->stop();
  esp_coex_preference_set(ESP_COEX_PREFER_BT);
  NimBLEScan *scan=NimBLEDevice::getScan();
  scan->setActiveScan(true);scan->setInterval(40);scan->setWindow(40);scan->setDuplicateFilter(false);
  addLog("BLE scan "+String(settings.scanSeconds)+"s");
  NimBLEScanResults results=scan->getResults((uint32_t)settings.scanSeconds*1000,false);
  addLog("Scan done: "+String(results.getCount())+" device(s)");
  String json="[";bool first=true;
  for(int i=0;i<results.getCount();i++){
    const NimBLEAdvertisedDevice *dev=results.getDevice(i);
    NimBLEAddress addr=dev->getAddress();
    String addrStr=String(addr.toString().c_str());addrStr.toUpperCase();
    String name=dev->haveName()?String(dev->getName().c_str()):"";
    int rssi=dev->getRSSI();
    String ats=(addr.getType()==BLE_ADDR_RANDOM)?"random":"public";
    bool wyze=isWyzeDevice(dev);
    addLog("  "+addrStr+" ["+ats+"] '"+name+"' rssi="+String(rssi)+(wyze?" [Wyze]":""));
    logDeviceDetail(dev);
    if(!first)json+=",";first=false;
    json+="{\"addr\":\""+jsonEscape(addrStr)+"\",\"addrType\":\""+ats+"\",\"name\":\""+jsonEscape(name)+"\",\"rssi\":"+String(rssi)+",\"wyze\":"+String(wyze?"true":"false")+"}";
  }
  json+="]";lastScanJson=json;
  scan->stop();scan->clearResults();
  scanRunning=false;
  esp_coex_preference_set(ESP_COEX_PREFER_BT);
  if(!gAdvConnected){NimBLEDevice::getAdvertising()->start();addLog("Adv resumed");}
  return lastScanJson;
}

// --------------------------------------------------------------------------
// Packet helpers
// --------------------------------------------------------------------------
bool isBleReady(){return gAdvConnected&&txChr;}
bool sendRawHex(const String &hex){std::vector<uint8_t>buf;if(!parseHexString(hex,buf)){addLog("Hex parse fail");return false;}return sendNotify(buf.data(),buf.size(),"RAW");}

static const uint8_t PKT_FF[8]    ={0xDE,0xC0,0xAD,0xDE,0xFF,0x01,0x1E,0xF1};
static const uint8_t PKT_FE[8]    ={0xDE,0xC0,0xAD,0xDE,0xFE,0x01,0x1E,0xF1};
static const uint8_t PKT_BIND[8]  ={0xDE,0xC0,0xAD,0xDE,0x01,0x1E,0xF1,0x00};
static const uint8_t PKT_UNLOCK[8]={0xDE,0xC0,0xAD,0xDE,0x00,0x01,0x1E,0xF1};
static const uint8_t PKT_KP[8]    ={0xDE,0xC0,0xAD,0xDE,0x02,0x01,0x1E,0xF1};

bool sendAuthResp(){
  if(!gNonceReceived){addLog("No nonce");return false;}
  uint8_t resp[8]={0};
  if(!computeAuthResponse(gLastNonce,resp)){addLog("AES fail");return false;}
  return sendNotify(resp,8,"AUTH_RESP_MANUAL");
}

// --------------------------------------------------------------------------
// State JSON
// --------------------------------------------------------------------------
String makeStateJson(){
  String json;json.reserve(4096);
  String ip=WiFi.status()==WL_CONNECTED?WiFi.localIP().toString():"";
  String apIp=portalMode?WiFi.softAPIP().toString():"";
  unsigned long tsc=(gAdvConnected&&gConnectedAtMs)?(millis()-gConnectedAtMs):0;
  json+="{";
  json+="\"hostname\":\""+String(HOSTNAME)+"\",";
  json+="\"wifiConnected\":"+String(WiFi.status()==WL_CONNECTED?"true":"false")+",";
  json+="\"portalMode\":"+String(portalMode?"true":"false")+",";
  json+="\"ip\":\""+jsonEscape(ip)+"\",\"apIp\":\""+jsonEscape(apIp)+"\",";
  json+="\"ssid\":\""+jsonEscape(settings.wifiSsid)+"\",";
  json+="\"mac\":\""+jsonEscape(WiFi.macAddress())+"\",";
  json+="\"rssi\":"+String(WiFi.status()==WL_CONNECTED?WiFi.RSSI():0)+",";
  json+="\"bleMode\":\"peripheral\",";
  json+="\"advConnected\":"+String(gAdvConnected?"true":"false")+",";
  json+="\"advPeer\":\""+jsonEscape(gAdvPeer)+"\",";
  json+="\"tSinceConnMs\":"+String(tsc)+",";
  json+="\"ownBleAddr\":\""+String(NimBLEDevice::getAddress().toString().c_str())+"\",";
  json+="\"advMode\":"+String(gAdvMode)+",";
  json+="\"useLockMac\":"+String(gUseLockMac?"true":"false")+",";
  json+="\"realLockMac\":\""+bytesToHex(REAL_LOCK_MAC,6)+"\",";
  json+="\"bleConnected\":"+String(isBleReady()?"true":"false")+",";
  json+="\"bleAddress\":\""+jsonEscape(settings.bleAddress)+"\",";
  json+="\"bleAddrType\":\""+jsonEscape(settings.bleAddrType)+"\",";
  json+="\"bleName\":\""+jsonEscape(settings.bleName)+"\",";
  json+="\"serviceUuid\":\""+jsonEscape(settings.serviceUuid)+"\",";
  json+="\"writeUuid\":\""+jsonEscape(settings.writeUuid)+"\",";
  json+="\"notifyUuid\":\""+jsonEscape(settings.notifyUuid)+"\",";
  json+="\"writeWithResponse\":"+String(settings.writeWithResponse?"true":"false")+",";
  json+="\"autoConnect\":"+String(settings.autoConnect?"true":"false")+",";
  json+="\"scanSeconds\":"+String(settings.scanSeconds)+",";
  json+="\"nonceReceived\":"+String(gNonceReceived?"true":"false")+",";
  json+="\"lastNonce\":\""+String(gNonceReceived?bytesToHex(gLastNonce,8):"")+"\",";
  json+="\"lastTx\":\""+jsonEscape(lastTxHex)+"\",\"lastRx\":\""+jsonEscape(lastRxHex)+"\",";
  json+="\"logs\":\""+jsonEscape(logBuffer)+"\",\"scan\":"+lastScanJson;
  json+="}";return json;
}

// --------------------------------------------------------------------------
// Web handlers
// --------------------------------------------------------------------------
void sendOk(const String &m){server.send(200,"application/json","{\"ok\":true,\"msg\":\""+jsonEscape(m)+"\"}");}
void sendErr(const String &m){server.send(200,"application/json","{\"ok\":false,\"msg\":\""+jsonEscape(m)+"\"}");}
bool argBool(const char *n,bool d){if(!server.hasArg(n))return d;String v=server.arg(n);v.toLowerCase();return v=="1"||v=="true"||v=="on"||v=="yes";}

void handleRoot()    {server.send_P(200,"text/html",INDEX_HTML);}
void handleState()   {server.send(200,"application/json",makeStateJson());}
void handleScan()    {server.send(200,"application/json",scanJson());}
void handleSaveConfig(){
  if(server.hasArg("bleAddress")){settings.bleAddress=server.arg("bleAddress");settings.bleAddress.trim();}
  if(server.hasArg("bleAddrType")){settings.bleAddrType=server.arg("bleAddrType");if(settings.bleAddrType!="random")settings.bleAddrType="public";}
  if(server.hasArg("bleName"))    settings.bleName    =server.arg("bleName");
  if(server.hasArg("serviceUuid")){settings.serviceUuid=server.arg("serviceUuid");settings.serviceUuid.trim();}
  if(server.hasArg("writeUuid")) {settings.writeUuid  =server.arg("writeUuid");settings.writeUuid.trim();}
  if(server.hasArg("notifyUuid")){settings.notifyUuid  =server.arg("notifyUuid");settings.notifyUuid.trim();}
  if(server.hasArg("scanSeconds")){int v=server.arg("scanSeconds").toInt();if(v<1)v=1;if(v>20)v=20;settings.scanSeconds=(uint8_t)v;}
  if(server.hasArg("mqttHost")) settings.mqttHost =server.arg("mqttHost");
  if(server.hasArg("mqttPort")) settings.mqttPort =(uint16_t)server.arg("mqttPort").toInt();
  if(server.hasArg("mqttUser")) settings.mqttUser =server.arg("mqttUser");
  if(server.hasArg("mqttPass")) settings.mqttPass =server.arg("mqttPass");
  if(server.hasArg("mqttTopic"))settings.mqttTopic=server.arg("mqttTopic");
  settings.autoConnect      =argBool("autoConnect",      settings.autoConnect);
  settings.writeWithResponse=argBool("writeWithResponse",settings.writeWithResponse);
  saveSettings();sendOk("Config saved");
}
void handleSaveWifi(){settings.wifiSsid=server.arg("ssid");settings.wifiPsk=server.arg("psk");saveSettings();beginWiFi(portalMode);sendOk("WiFi saved");}
void handleClearBonds(){NimBLEDevice::deleteAllBonds();addLog("Bonds cleared");sendOk("Bonds cleared");}
void handleStartAdv(){startAdvertising();sendOk("Adv started");}
void handleStopAdv() {stopAdvertising();sendOk("Adv stopped");}
void handleTryLockMac(){
  gUseLockMac=true;
  NimBLEDevice::getAdvertising()->stop();delay(100);startAdvertising();
  sendOk("Adv with real lock MAC: "+bytesToHex(REAL_LOCK_MAC,6));
}
void handleUseOwnMac(){
  gUseLockMac=false;
  NimBLEDevice::getAdvertising()->stop();delay(100);startAdvertising();
  sendOk("Adv with own MAC");
}
void handleAdvMode(){
  if(server.hasArg("mode")) gAdvMode=server.arg("mode").toInt();
  else gAdvMode=(gAdvMode==0)?1:0;
  NimBLEDevice::getAdvertising()->stop();delay(100);startAdvertising();
  sendOk("advMode="+String(gAdvMode)+(gAdvMode==0?" (180F only)":" (180F+FE50)"));
}
void handleSendFF()    {sendNotify(PKT_FF,   sizeof(PKT_FF),   "FF"   )?sendOk("Sent"):sendErr("Fail");}
void handleSendFE()    {sendNotify(PKT_FE,   sizeof(PKT_FE),   "FE"   )?sendOk("Sent"):sendErr("Fail");}
void handleSendBind()  {sendNotify(PKT_BIND, sizeof(PKT_BIND), "BIND" )?sendOk("Sent"):sendErr("Fail");}
void handleSendUnlock(){sendNotify(PKT_UNLOCK,sizeof(PKT_UNLOCK),"UNLOCK")?sendOk("Sent"):sendErr("Fail");}
void handleSendKP()    {sendNotify(PKT_KP,   sizeof(PKT_KP),   "KP"   )?sendOk("Sent"):sendErr("Fail");}
void handleSendRaw()   {sendRawHex(server.arg("hex"))?sendOk("Sent"):sendErr("Fail");}
void handleClearLog()  {logBuffer="";lastTxHex="";lastRxHex="";sendOk("Cleared");}
void handleReboot()    {sendOk("Rebooting");delay(200);ESP.restart();}
void handleSendAuthResp(){sendAuthResp()?sendOk("Sent"):sendErr("Fail");}
void handleSendNotify() {sendRawHex(server.arg("hex"))?sendOk("Sent"):sendErr("Fail");}

void setupWeb(){
  server.on("/",HTTP_GET,handleRoot);
  server.on("/api/state",HTTP_GET,handleState);
  server.on("/api/scan",HTTP_GET,handleScan);
  server.on("/api/saveConfig",HTTP_POST,handleSaveConfig);
  server.on("/api/saveWifi",HTTP_POST,handleSaveWifi);
  server.on("/api/startAdv",HTTP_POST,handleStartAdv);
  server.on("/api/stopAdv",HTTP_POST,handleStopAdv);
  server.on("/api/tryLockMac",HTTP_POST,handleTryLockMac);
  server.on("/api/useOwnMac",HTTP_POST,handleUseOwnMac);
  server.on("/api/advMode",HTTP_POST,handleAdvMode);
  server.on("/api/sendFF",HTTP_POST,handleSendFF);
  server.on("/api/sendFE",HTTP_POST,handleSendFE);
  server.on("/api/sendBind",HTTP_POST,handleSendBind);
  server.on("/api/sendUnlock",HTTP_POST,handleSendUnlock);
  server.on("/api/sendKP",HTTP_POST,handleSendKP);
  server.on("/api/sendRaw",HTTP_POST,handleSendRaw);
  server.on("/api/clearLog",HTTP_POST,handleClearLog);
  server.on("/api/clearBonds",HTTP_POST,handleClearBonds);
  server.on("/api/reboot",HTTP_POST,handleReboot);
  server.on("/api/sendAuthResp",HTTP_POST,handleSendAuthResp);
  server.on("/api/sendNotify",HTTP_POST,handleSendNotify);
  server.onNotFound([](){if(portalMode){server.sendHeader("Location","/",true);server.send(302,"text/plain","");}else server.send(404,"text/plain","Not found");});
  server.begin();addLog("HTTP started");
}

void serviceWiFi(){
  bool up=(WiFi.status()==WL_CONNECTED);
  if(up&&!wifiWasConnected){wifiWasConnected=true;addLog("WiFi up: "+WiFi.localIP().toString());ensureMDNSOTA();stopPortal();}
  if(!up&&wifiWasConnected){wifiWasConnected=false;addLog("WiFi down");lastWifiTryMs=millis();}
  if(!up){if(millis()-lastWifiTryMs>15000)beginWiFi(portalMode);if(!portalMode&&millis()>30000&&millis()-lastWifiTryMs>10000)startPortal();}
}

void setup(){
  DBG_BEGIN(115200);delay(200);addLog("Boot r10d");
  loadSettings();
  addLog("AES key: "+bytesToHex(AES_KEY,16));
  addLog("Real lock MAC: "+bytesToHex(REAL_LOCK_MAC,6));
  addLog("r10d: PERIPHERAL, adv=180F only (real lock match)");
  WiFi.disconnect(true,true);delay(200);
  beginWiFi(false);
  NimBLEDevice::init("Wyze Lock");
  NimBLEDevice::setPower(9);
  NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_RANDOM);
  addLog("Own BLE addr: "+String(NimBLEDevice::getAddress().toString().c_str()));
  NimBLEDevice::setSecurityAuth(0);
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_NO_INPUT_OUTPUT);
  setupBlePeripheral();
  setupWeb();
  unsigned long t0=millis();
  while(WiFi.status()!=WL_CONNECTED&&millis()-t0<12000){delay(100);server.handleClient();}
  if(WiFi.status()!=WL_CONNECTED){addLog("WiFi timeout -> portal");startPortal();}
  else ensureMDNSOTA();
}

void loop(){
  server.handleClient();
  if(portalMode)dns.processNextRequest();
  if(otaReady&&WiFi.status()==WL_CONNECTED)ArduinoOTA.handle();
  serviceWiFi();serviceMQTT();
  if(millis()-lastStateMs>10000){
    lastStateMs=millis();
    addLog("heartbeat wifi="+String(WiFi.status()==WL_CONNECTED?"up":"down")
           +" ble="+String(gAdvConnected?"CONNECTED":"adv")
           +" advMode="+String(gAdvMode)
           +" lockMac="+String(gUseLockMac?"yes":"no")
           +" nonce="+String(gNonceReceived?"yes":"wait")
           +" t+conn="+String((gAdvConnected&&gConnectedAtMs)?(millis()-gConnectedAtMs):0)+"ms");
  }
  delay(5);
}
