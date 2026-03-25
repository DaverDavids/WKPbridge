// WKPbridge.ino
// ESP32-C3 BLE-to-WiFi bridge for Wyze Wireless Keypad (WLCKKP1)
//
// Fix log:
//  r1-r9:  scan/connect/decompile (see git history)
//  r10:    Flip to PERIPHERAL mode (wrong -- keypad is peripheral)
//  r10a-d: Various adv tuning, all wrong direction
//  r10e:   ROLE REVERSAL: Bridge is CENTRAL, connects TO keypad
//  r10f:   setCallbacks -> setClientCallbacks
//  r10g:   Fix auto* deduction
//  r10h:   getServices const ref; UART1 sniffer added
//  r10i:   NimBLE 2.x fixes:
//            - remove discoverAttributes() (does not exist in 2.x)
//            - getServices() returns value not pointer; remove * dereference

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

static const uint8_t AES_KEY[16] = {
  0xD3, 0x7F, 0xCD, 0x69, 0x03, 0xFE, 0x6E, 0x69,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const char *KEYPAD_MAC = "e2:79:a5:dc:36:4d";

// UART1 sniffer -- GPIO20=RX (listen), GPIO21=TX (send)
#define UART1_RX_PIN 20
#define UART1_TX_PIN 21
#define SERIAL1_BUF  4096
static String   gSerial1Buf;
static uint32_t gSerial1Baud    = 115200;
static uint8_t  gSerial1Config  = SERIAL_8N1;
static bool     gSerial1Open    = false;
static bool     gSerial1HexMode = false;

static NimBLEClient               *bleClient   = nullptr;
static NimBLERemoteCharacteristic *txNotifyChr = nullptr;
static NimBLERemoteCharacteristic *rxWriteChr  = nullptr;
static bool          gConnected     = false;
static unsigned long gConnectedAtMs = 0;
static unsigned long gLastConnTryMs = 0;
static bool          gConnecting    = false;

static uint8_t gLastNonce[8] = {0};
static bool    gNonceReceived = false;

#if DEBUG_SERIAL
  #define DBG_BEGIN(x)   Serial.begin(x)
  #define DBG_PRINTLN(x) Serial.println(x)
#else
  #define DBG_BEGIN(x)
  #define DBG_PRINTLN(x)
#endif

struct Settings {
  String  wifiSsid, wifiPsk;
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
// UART1 sniffer
// --------------------------------------------------------------------------
void serial1Open(uint32_t baud, uint8_t cfg){
  if(gSerial1Open) Serial1.end();
  gSerial1Baud=baud; gSerial1Config=cfg;
  Serial1.begin(baud, cfg, UART1_RX_PIN, UART1_TX_PIN);
  gSerial1Open=true;
  addLog("UART1 open baud="+String(baud)+" cfg=0x"+String(cfg,HEX)+" RX=GPIO"+String(UART1_RX_PIN)+" TX=GPIO"+String(UART1_TX_PIN));
}
void serviceSerial1(){
  if(!gSerial1Open) return;
  while(Serial1.available()){
    if(gSerial1HexMode){
      uint8_t b=(uint8_t)Serial1.read();
      const char *h="0123456789ABCDEF";
      gSerial1Buf+=h[(b>>4)&0xF]; gSerial1Buf+=h[b&0xF]; gSerial1Buf+=' ';
    } else {
      char c=(char)Serial1.read();
      if(c=='\r') continue;
      gSerial1Buf+=c;
    }
    if(gSerial1Buf.length()>SERIAL1_BUF)
      gSerial1Buf.remove(0, gSerial1Buf.length()-SERIAL1_BUF);
  }
}

// --------------------------------------------------------------------------
// Settings
// --------------------------------------------------------------------------
void loadSettings(){
  prefs.begin("wkpbridge",true);
  settings.wifiSsid    =prefs.getString("wifi_ssid",MYSSID);
  settings.wifiPsk     =prefs.getString("wifi_psk", MYPSK);
  settings.scanSeconds =prefs.getUChar("scan_sec",5);
  settings.mqttHost =prefs.getString("mqtt_host",""); settings.mqttPort=prefs.getUShort("mqtt_port",1883);
  settings.mqttUser =prefs.getString("mqtt_user",""); settings.mqttPass=prefs.getString("mqtt_pass","");
  settings.mqttTopic=prefs.getString("mqtt_topic","wkpbridge");
  prefs.end();
}
void saveSettings(){
  prefs.begin("wkpbridge",false);
  prefs.putString("wifi_ssid",settings.wifiSsid); prefs.putString("wifi_psk",settings.wifiPsk);
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
  WiFi.setTxPower(WIFI_POWER_11dBm); lastWifiTryMs=millis();
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
// Write to keypad RX characteristic (bridge -> keypad)
// --------------------------------------------------------------------------
bool writeToKeypad(const uint8_t *d, size_t l, const char *tag){
  if(!gConnected||!rxWriteChr){addLog(String("WRITE failed: not connected - ")+tag);return false;}
  lastTxHex=bytesToHex(d,l);
  addLog(String("WRITE ")+tag+": "+lastTxHex);
  bool ok=rxWriteChr->writeValue(d,l,false);
  addLog(String("WRITE result: ")+(ok?"OK":"FAIL"));
  return ok;
}

// --------------------------------------------------------------------------
// Notify callback -- keypad TX -> bridge
// --------------------------------------------------------------------------
void onKeypadNotify(NimBLERemoteCharacteristic*, uint8_t *d, size_t l, bool isNotify){
  lastRxHex=bytesToHex(d,l);
  unsigned long t=gConnectedAtMs?(millis()-gConnectedAtMs):0;
  addLog("KP->BRIDGE notify len="+String(l)+" t+"+String(t)+"ms");
  addLog("  RAW: "+lastRxHex);
  if(l==8){
    addLog("  -> 8-byte NONCE");
    memcpy(gLastNonce,d,8); gNonceReceived=true;
    uint8_t resp[8]={0};
    if(computeAuthResponse(gLastNonce,resp)){
      addLog("  -> AES resp: "+bytesToHex(resp,8));
      delay(20);
      bool ok=writeToKeypad(resp,8,"AUTH_RESP");
      addLog(ok?"  -> Auth write OK":"  -> Auth write FAILED");
    } else addLog("  -> AES FAILED");
    mqttPublish(lastRxHex); return;
  }
  if(l>=5&&d[0]==0xDE&&d[1]==0xC0&&d[2]==0xAD&&d[3]==0xDE){
    uint8_t op=d[4]; String opName;
    switch(op){
      case 0x00:opName="UNLOCK";break; case 0x01:opName="BIND";break;
      case 0x02:opName="KEYPRESS";break; case 0xFE:opName="PROBE_FE";break;
      case 0xFF:opName="GET_RANDOM";break;
      default:opName="OP_0x"+String(op,HEX);
    }
    addLog("  -> dd_proto op="+opName+" payload="+((l>5)?bytesToHex(d+5,l-5):String("(none)")));
    mqttPublish(lastRxHex); return;
  }
  addLog("  -> Unknown len="+String(l));
  mqttPublish(lastRxHex);
}

// --------------------------------------------------------------------------
// BLE client callbacks
// --------------------------------------------------------------------------
class ClientCB : public NimBLEClientCallbacks {
  void onConnect(NimBLEClient *c) override {
    gConnected=true; gConnectedAtMs=millis(); gConnecting=false;
    addLog(">>> CONNECTED to keypad "+String(c->getPeerAddress().toString().c_str()));
  }
  void onDisconnect(NimBLEClient *c, int reason) override {
    unsigned long dur=gConnectedAtMs?(millis()-gConnectedAtMs):0;
    addLog(">>> DISCONNECTED reason=0x"+String(reason,HEX)+" dur="+String(dur)+"ms nonce="+String(gNonceReceived?"YES":"NO"));
    gConnected=false; gConnectedAtMs=0; gConnecting=false;
    gNonceReceived=false; txNotifyChr=nullptr; rxWriteChr=nullptr;
    gLastConnTryMs=millis();
  }
};
ClientCB gClientCB;

// --------------------------------------------------------------------------
// Connect to keypad
// --------------------------------------------------------------------------
bool connectToKeypad(){
  if(gConnected||gConnecting)return gConnected;
  gConnecting=true;
  addLog("Connecting to keypad "+String(KEYPAD_MAC)+" ...");

  if(!bleClient){
    bleClient=NimBLEDevice::createClient();
    bleClient->setClientCallbacks(&gClientCB);
    bleClient->setConnectionParams(12,12,0,51);
    bleClient->setConnectTimeout(5);
  }

  NimBLEAddress kpAddr(KEYPAD_MAC, BLE_ADDR_RANDOM);
  if(!bleClient->connect(kpAddr)){
    addLog("Connect FAILED");
    gConnecting=false; gLastConnTryMs=millis(); return false;
  }
  // NimBLE 2.x: connect() triggers service/char discovery automatically.
  // getService() will use cached results.

  NimBLERemoteService *nus=bleClient->getService(NUS_SERVICE_UUID);
  if(!nus){
    addLog("NUS NOT FOUND -- all services:");
    // NimBLE 2.x getServices() returns a const std::vector by value -- no pointer, no dereference
    std::vector<NimBLERemoteService*> svcs = bleClient->getServices(true);
    for(NimBLERemoteService *svc : svcs)
      addLog("  svc: "+String(svc->getUUID().toString().c_str()));
    bleClient->disconnect(); gConnecting=false; gLastConnTryMs=millis(); return false;
  }
  addLog("NUS service found");

  txNotifyChr=nus->getCharacteristic(NUS_TX_UUID);
  rxWriteChr =nus->getCharacteristic(NUS_RX_UUID);
  if(!txNotifyChr||!rxWriteChr){
    addLog("NUS chr MISSING tx="+String(txNotifyChr?"OK":"NO")+" rx="+String(rxWriteChr?"OK":"NO"));
    bleClient->disconnect(); gConnecting=false; gLastConnTryMs=millis(); return false;
  }
  if(!txNotifyChr->canNotify()){
    addLog("TX chr cannot notify");
    bleClient->disconnect(); gConnecting=false; gLastConnTryMs=millis(); return false;
  }

  addLog("Subscribing to keypad TX notify...");
  bool subOk=txNotifyChr->subscribe(true, onKeypadNotify, false);
  addLog("Subscribe: "+(subOk?String("OK"):String("FAIL")));
  if(!subOk){
    bleClient->disconnect(); gConnecting=false; gLastConnTryMs=millis(); return false;
  }

  addLog("Ready. Waiting for keypad nonce...");
  gConnecting=false;
  return true;
}

// --------------------------------------------------------------------------
// Scan (diagnostic)
// --------------------------------------------------------------------------
bool isWyzeDevice(const NimBLEAdvertisedDevice *dev){
  if(dev->haveManufacturerData()){const std::string &m=dev->getManufacturerData();if(m.size()>=2&&(((uint8_t)m[0]|((uint8_t)m[1]<<8))==WYZE_COMPANY_ID))return true;}
  if(dev->haveName()){std::string n=dev->getName();if(n=="Wyze Lock"||n=="KP-01"||n=="DingDing")return true;}
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
  if(sc>0){addLog("    advUUIDs("+String(sc)+"):");for(int i=0;i<sc;i++)addLog("      "+String(dev->getServiceUUID(i).toString().c_str()));}
  else addLog("    No adv UUIDs");
}
String scanJson(){
  if(gConnected){addLog("Scan skipped: connected");return lastScanJson;}
  if(scanRunning){addLog("Scan busy");return lastScanJson;}
  scanRunning=true;
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
  return lastScanJson;
}

// --------------------------------------------------------------------------
// Packet helpers
// --------------------------------------------------------------------------
bool isBleReady(){return gConnected&&rxWriteChr;}
static const uint8_t PKT_FF[8]    ={0xDE,0xC0,0xAD,0xDE,0xFF,0x01,0x1E,0xF1};
static const uint8_t PKT_FE[8]    ={0xDE,0xC0,0xAD,0xDE,0xFE,0x01,0x1E,0xF1};
static const uint8_t PKT_BIND[8]  ={0xDE,0xC0,0xAD,0xDE,0x01,0x1E,0xF1,0x00};
static const uint8_t PKT_UNLOCK[8]={0xDE,0xC0,0xAD,0xDE,0x00,0x01,0x1E,0xF1};
static const uint8_t PKT_KP[8]    ={0xDE,0xC0,0xAD,0xDE,0x02,0x01,0x1E,0xF1};
bool sendAuthResp(){
  if(!gNonceReceived){addLog("No nonce yet");return false;}
  uint8_t resp[8]={0};
  if(!computeAuthResponse(gLastNonce,resp)){addLog("AES fail");return false;}
  return writeToKeypad(resp,8,"AUTH_RESP_MANUAL");
}
bool sendRawHex(const String &hex){
  std::vector<uint8_t>buf;
  if(!parseHexString(hex,buf)){addLog("Hex parse fail");return false;}
  return writeToKeypad(buf.data(),buf.size(),"RAW");
}

// --------------------------------------------------------------------------
// State JSON
// --------------------------------------------------------------------------
String makeStateJson(){
  String json;json.reserve(4096);
  String ip=WiFi.status()==WL_CONNECTED?WiFi.localIP().toString():"";
  String apIp=portalMode?WiFi.softAPIP().toString():"";
  unsigned long tsc=(gConnected&&gConnectedAtMs)?(millis()-gConnectedAtMs):0;
  json+="{";
  json+="\"hostname\":\""+String(HOSTNAME)+"\",";
  json+="\"wifiConnected\":"+String(WiFi.status()==WL_CONNECTED?"true":"false")+",";
  json+="\"portalMode\":"+String(portalMode?"true":"false")+",";
  json+="\"ip\":\""+jsonEscape(ip)+"\",\"apIp\":\""+jsonEscape(apIp)+"\",";
  json+="\"ssid\":\""+jsonEscape(settings.wifiSsid)+"\",";
  json+="\"mac\":\""+jsonEscape(WiFi.macAddress())+"\",";
  json+="\"rssi\":"+String(WiFi.status()==WL_CONNECTED?WiFi.RSSI():0)+",";
  json+="\"bleMode\":\"central\",";
  json+="\"bleConnected\":"+String(gConnected?"true":"false")+",";
  json+="\"keypadMac\":\""+String(KEYPAD_MAC)+"\",";
  json+="\"tSinceConnMs\":"+String(tsc)+",";
  json+="\"ownBleAddr\":\""+String(NimBLEDevice::getAddress().toString().c_str())+"\",";
  json+="\"nonceReceived\":"+String(gNonceReceived?"true":"false")+",";
  json+="\"lastNonce\":\""+String(gNonceReceived?bytesToHex(gLastNonce,8):"")+"\",";
  json+="\"lastTx\":\""+jsonEscape(lastTxHex)+"\",\"lastRx\":\""+jsonEscape(lastRxHex)+"\",";
  json+="\"uart1Open\":"+String(gSerial1Open?"true":"false")+",";
  json+="\"uart1Baud\":"+String(gSerial1Baud)+",";
  json+="\"uart1HexMode\":"+String(gSerial1HexMode?"true":"false")+",";
  json+="\"logs\":\""+jsonEscape(logBuffer)+"\",\"scan\":"+lastScanJson;
  json+="}";return json;
}

// --------------------------------------------------------------------------
// Web handlers
// --------------------------------------------------------------------------
void sendOk(const String &m){server.send(200,"application/json","{\"ok\":true,\"msg\":\""+jsonEscape(m)+"\"}");}
void sendErr(const String &m){server.send(200,"application/json","{\"ok\":false,\"msg\":\""+jsonEscape(m)+"\"}");}
void handleRoot()    {server.send_P(200,"text/html",INDEX_HTML);}
void handleState()   {server.send(200,"application/json",makeStateJson());}
void handleScan()    {server.send(200,"application/json",scanJson());}
void handleConnect() {connectToKeypad()?sendOk("Connected"):sendErr("Failed");}
void handleDisconnect(){if(bleClient&&bleClient->isConnected())bleClient->disconnect();sendOk("Disconnected");}
void handleSaveWifi(){settings.wifiSsid=server.arg("ssid");settings.wifiPsk=server.arg("psk");saveSettings();beginWiFi(portalMode);sendOk("WiFi saved");}
void handleClearBonds(){NimBLEDevice::deleteAllBonds();addLog("Bonds cleared");sendOk("Bonds cleared");}
void handleSendFF()    {writeToKeypad(PKT_FF,   sizeof(PKT_FF),   "FF"   )?sendOk("Sent"):sendErr("Fail");}
void handleSendFE()    {writeToKeypad(PKT_FE,   sizeof(PKT_FE),   "FE"   )?sendOk("Sent"):sendErr("Fail");}
void handleSendBind()  {writeToKeypad(PKT_BIND, sizeof(PKT_BIND), "BIND" )?sendOk("Sent"):sendErr("Fail");}
void handleSendUnlock(){writeToKeypad(PKT_UNLOCK,sizeof(PKT_UNLOCK),"UNLOCK")?sendOk("Sent"):sendErr("Fail");}
void handleSendKP()    {writeToKeypad(PKT_KP,   sizeof(PKT_KP),   "KP"   )?sendOk("Sent"):sendErr("Fail");}
void handleSendRaw()   {sendRawHex(server.arg("hex"))?sendOk("Sent"):sendErr("Fail");}
void handleClearLog()  {logBuffer="";lastTxHex="";lastRxHex="";sendOk("Cleared");}
void handleReboot()    {sendOk("Rebooting");delay(200);ESP.restart();}
void handleSendAuthResp(){sendAuthResp()?sendOk("Sent"):sendErr("Fail");}
void handleSendNotify() {sendRawHex(server.arg("hex"))?sendOk("Sent"):sendErr("Fail");}
void handleSerial1Config(){
  uint32_t baud=server.hasArg("baud")?(uint32_t)server.arg("baud").toInt():gSerial1Baud;
  String cfgStr=server.hasArg("cfg")?server.arg("cfg"):"8N1";
  uint8_t cfg=SERIAL_8N1;
  if(cfgStr=="8E1")cfg=SERIAL_8E1;
  else if(cfgStr=="8O1")cfg=SERIAL_8O1;
  else if(cfgStr=="7N1")cfg=SERIAL_7N1;
  else if(cfgStr=="7E1")cfg=SERIAL_7E1;
  else if(cfgStr=="7O1")cfg=SERIAL_7O1;
  if(server.hasArg("hex"))gSerial1HexMode=(server.arg("hex")=="1"||server.arg("hex")=="true");
  serial1Open(baud,cfg);
  sendOk("UART1 opened baud="+String(baud)+" cfg="+cfgStr);
}
void handleSerial1Read(){
  String data=gSerial1Buf; gSerial1Buf="";
  server.send(200,"application/json","{\"ok\":true,\"data\":\""+jsonEscape(data)+"\",\"baud\":"+String(gSerial1Baud)+",\"open\":"+String(gSerial1Open?"true":"false")+"}");
}
void handleSerial1Write(){
  if(!gSerial1Open){sendErr("UART1 not open");return;}
  String hex=server.arg("hex"); String txt=server.arg("txt");
  if(hex.length()){std::vector<uint8_t>buf;if(!parseHexString(hex,buf)){sendErr("hex parse");return;}Serial1.write(buf.data(),buf.size());sendOk("Sent "+String(buf.size())+"b hex");}
  else if(txt.length()){Serial1.print(txt);sendOk("Sent "+String(txt.length())+"b txt");}
  else sendErr("no data");
}
void handleSerial1Close(){if(gSerial1Open){Serial1.end();gSerial1Open=false;}sendOk("UART1 closed");}
void handleSerial1ClearBuf(){gSerial1Buf="";sendOk("UART1 buf cleared");}
void handleSaveConfig(){
  if(server.hasArg("scanSeconds")){int v=server.arg("scanSeconds").toInt();if(v<1)v=1;if(v>20)v=20;settings.scanSeconds=(uint8_t)v;}
  if(server.hasArg("mqttHost")) settings.mqttHost =server.arg("mqttHost");
  if(server.hasArg("mqttPort")) settings.mqttPort =(uint16_t)server.arg("mqttPort").toInt();
  if(server.hasArg("mqttUser")) settings.mqttUser =server.arg("mqttUser");
  if(server.hasArg("mqttPass")) settings.mqttPass =server.arg("mqttPass");
  if(server.hasArg("mqttTopic"))settings.mqttTopic=server.arg("mqttTopic");
  saveSettings();sendOk("Config saved");
}
void setupWeb(){
  server.on("/",HTTP_GET,handleRoot);
  server.on("/api/state",HTTP_GET,handleState);
  server.on("/api/scan",HTTP_GET,handleScan);
  server.on("/api/connect",HTTP_POST,handleConnect);
  server.on("/api/disconnect",HTTP_POST,handleDisconnect);
  server.on("/api/saveConfig",HTTP_POST,handleSaveConfig);
  server.on("/api/saveWifi",HTTP_POST,handleSaveWifi);
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
  server.on("/api/serial/config",HTTP_POST,handleSerial1Config);
  server.on("/api/serial/read",HTTP_GET,handleSerial1Read);
  server.on("/api/serial/write",HTTP_POST,handleSerial1Write);
  server.on("/api/serial/close",HTTP_POST,handleSerial1Close);
  server.on("/api/serial/clear",HTTP_POST,handleSerial1ClearBuf);
  server.onNotFound([](){if(portalMode){server.sendHeader("Location","/",true);server.send(302,"text/plain","");}else server.send(404,"text/plain","Not found");});
  server.begin();addLog("HTTP started");
}
void serviceWiFi(){
  bool up=(WiFi.status()==WL_CONNECTED);
  if(up&&!wifiWasConnected){wifiWasConnected=true;addLog("WiFi up: "+WiFi.localIP().toString());ensureMDNSOTA();stopPortal();}
  if(!up&&wifiWasConnected){wifiWasConnected=false;addLog("WiFi down");lastWifiTryMs=millis();}
  if(!up){if(millis()-lastWifiTryMs>15000)beginWiFi(portalMode);if(!portalMode&&millis()>30000&&millis()-lastWifiTryMs>10000)startPortal();}
}
void serviceBLE(){
  if(gConnected||gConnecting||scanRunning)return;
  if(millis()-gLastConnTryMs>5000){
    gLastConnTryMs=millis();
    connectToKeypad();
  }
}
void setup(){
  DBG_BEGIN(115200);delay(200);addLog("Boot r10i");
  loadSettings();
  addLog("AES key: "+bytesToHex(AES_KEY,16));
  addLog("Keypad MAC (target): "+String(KEYPAD_MAC));
  addLog("r10i: CENTRAL -- connecting TO keypad");
  addLog("UART1 sniffer: RX=GPIO"+String(UART1_RX_PIN)+" TX=GPIO"+String(UART1_TX_PIN));
  WiFi.disconnect(true,true);delay(200);
  beginWiFi(false);
  NimBLEDevice::init("");
  NimBLEDevice::setPower(9);
  NimBLEDevice::setSecurityAuth(0);
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_NO_INPUT_OUTPUT);
  esp_coex_preference_set(ESP_COEX_PREFER_BT);
  addLog("Own BLE addr: "+String(NimBLEDevice::getAddress().toString().c_str()));
  setupWeb();
  unsigned long t0=millis();
  while(WiFi.status()!=WL_CONNECTED&&millis()-t0<12000){delay(100);server.handleClient();}
  if(WiFi.status()!=WL_CONNECTED){addLog("WiFi timeout -> portal");startPortal();}
  else ensureMDNSOTA();
  addLog("Will auto-connect to keypad in 5s...");
}
void loop(){
  server.handleClient();
  if(portalMode)dns.processNextRequest();
  if(otaReady&&WiFi.status()==WL_CONNECTED)ArduinoOTA.handle();
  serviceWiFi();serviceMQTT();serviceBLE();serviceSerial1();
  if(millis()-lastStateMs>10000){
    lastStateMs=millis();
    addLog("heartbeat wifi="+String(WiFi.status()==WL_CONNECTED?"up":"down")
           +" ble="+String(gConnected?"CONNECTED":"disconnected")
           +" nonce="+String(gNonceReceived?"yes":"wait")
           +" t+conn="+String((gConnected&&gConnectedAtMs)?(millis()-gConnectedAtMs):0)+"ms"
           +" uart1="+String(gSerial1Open?String(gSerial1Baud)+"bd":"closed"));
  }
  delay(5);
}
