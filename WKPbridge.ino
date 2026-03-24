// WKPbridge.ino
// ESP32-C3 BLE-to-WiFi bridge for Wyze Wireless Keypad (WLCKKP1)
//
// Fix log:
//  r1-r5: scan/connect fixes, debug
//  r6: Dump full manufacturer data bytes from advertisement.
//      Wyze keypad adv mfr data byte[8] = 0x0A if paired, 0x00 if unpaired.
//      Also: on connect failure, log exact HCI status code from
//      onConnectFail reason (this is the raw HCI error, not ble_hs wrapping).

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

#include <Secrets.h>
#include "html.h"

static const char *HOSTNAME = "WKPbridge";
static const char *AP_SSID  = "WKPbridge-setup";
static const byte DNS_PORT  = 53;

static const char *NUS_SERVICE_UUID = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
static const char *NUS_RX_UUID      = "6e400002-b5a3-f393-e0a9-e50e24dcca9e";
static const char *NUS_TX_UUID      = "6e400003-b5a3-f393-e0a9-e50e24dcca9e";
static const uint16_t WYZE_COMPANY_ID = 0x4459;

#if DEBUG_SERIAL
  #define DBG_BEGIN(x)    Serial.begin(x)
  #define DBG_PRINTLN(x)  Serial.println(x)
#else
  #define DBG_BEGIN(x)
  #define DBG_PRINTLN(x)
#endif

static const char* nimbleErrStr(int err) {
  switch(err) {
    case 0x00: return "OK";
    case 0x01: return "BLE_HS_EAGAIN";
    case 0x02: return "BLE_HS_EALREADY";
    case 0x03: return "BLE_HS_EINVAL";
    case 0x04: return "BLE_HS_EMSGSIZE";
    case 0x05: return "BLE_HS_ENOENT";
    case 0x06: return "BLE_HS_ENOMEM";
    case 0x07: return "BLE_HS_ENOTCONN";
    case 0x08: return "BLE_HS_ENOTSUP";
    case 0x09: return "BLE_HS_EAPP";
    case 0x0a: return "BLE_HS_EBADDATA";
    case 0x0b: return "BLE_HS_EOS";
    case 0x0c: return "BLE_HS_ECONTROLLER";
    case 0x0d: return "BLE_HS_ETIMEOUT";
    case 0x0e: return "BLE_HS_EDONE";
    case 0x0f: return "BLE_HS_EBUSY";
    case 0x10: return "BLE_HS_EREJECT";
    case 0x11: return "BLE_HS_EUNKNOWN";
    case 0x12: return "BLE_HS_EROLE";
    case 0x13: return "BLE_HS_ETIMEOUT_HCI";
    case 0x14: return "BLE_HS_ENOMEM_EVT";
    case 0x15: return "BLE_HS_ENOADDR";
    case 0x16: return "BLE_HS_ENOTSYNCED";
    case 0x17: return "BLE_HS_EAUTHEN";
    case 0x18: return "BLE_HS_EAUTHOR";
    case 0x19: return "BLE_HS_EENCRYPT";
    case 0x1a: return "BLE_HS_EENCRYPT_KEY_SZ";
    case 0x1b: return "BLE_HS_ESTORE_CAP";
    case 0x1c: return "BLE_HS_ESTORE_FAIL";
    case 0x1d: return "BLE_HS_EPREEMPTED";
    case 0x1e: return "BLE_HS_EDISABLED";
    case 0x1f: return "BLE_HS_ESTALLED";
    default:   return "UNKNOWN";
  }
}

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
unsigned long lastWifiTryMs=0, lastBleTryMs=0, lastStateMs=0;

String logBuffer, lastScanJson="[]", lastTxHex, lastRxHex, currentTargetAddr;

static uint8_t  gFoundAddrBytes[6];
static uint8_t  gFoundAddrType = BLE_ADDR_RANDOM;
static bool     gFoundValid    = false;

NimBLEClient               *bleClient = nullptr;
NimBLERemoteCharacteristic *writeChr  = nullptr;
NimBLERemoteCharacteristic *notifyChr = nullptr;

static const uint8_t PKT_FF[8] = {0xDE,0xC0,0xAD,0xDE,0xFF,0x01,0x1E,0xF1};
static const uint8_t PKT_FE[8] = {0xDE,0xC0,0xAD,0xDE,0xFE,0x01,0x1E,0xF1};

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------
String jsonEscape(const String &in) {
  String out; out.reserve(in.length()+16);
  for(size_t i=0;i<in.length();i++){
    char c=in[i]; switch(c){
      case '\\': out+="\\\\"; break; case '"': out+="\\\""; break;
      case '\n': out+="\\n";  break; case '\r': break;
      case '\t': out+="\\t";  break;
      default: if((uint8_t)c<32)out+=' '; else out+=c; break;
    }
  }
  return out;
}
void addLog(const String &line){
  String s=String(millis())+" | "+line; logBuffer+=s+"\n";
  if(logBuffer.length()>14000)logBuffer.remove(0,logBuffer.length()-14000);
  DBG_PRINTLN(s);
}
String bytesToHex(const uint8_t *d,size_t l){
  const char *h="0123456789ABCDEF"; String o; o.reserve(l*3);
  for(size_t i=0;i<l;i++){o+=h[(d[i]>>4)&0xF];o+=h[d[i]&0xF];if(i+1<l)o+=' ';} return o;
}
bool parseHexString(String s,std::vector<uint8_t>&out){
  out.clear();s.replace("0x","");s.replace("0X","");s.replace(","," ");s.replace(":"," ");s.replace("-"," ");
  while(s.indexOf("  ")>=0)s.replace("  "," ");s.trim();if(s.isEmpty())return false;
  int st=0;
  while(st<(int)s.length()){
    while(st<(int)s.length()&&s[st]==' ')st++;if(st>=(int)s.length())break;
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
  settings.bleName     =prefs.getString("ble_name", "Wyze Lock");
  settings.serviceUuid =prefs.getString("svc_uuid", NUS_SERVICE_UUID);
  settings.writeUuid   =prefs.getString("wr_uuid",  NUS_RX_UUID);
  settings.notifyUuid  =prefs.getString("nt_uuid",  NUS_TX_UUID);
  settings.autoConnect      =prefs.getBool  ("auto_conn",false);
  settings.writeWithResponse=prefs.getBool  ("wr_rsp",   false);
  settings.scanSeconds      =prefs.getUChar ("scan_sec", 5);
  settings.mqttHost=prefs.getString("mqtt_host","");settings.mqttPort=prefs.getUShort("mqtt_port",1883);
  settings.mqttUser=prefs.getString("mqtt_user","");settings.mqttPass=prefs.getString("mqtt_pass","");
  settings.mqttTopic=prefs.getString("mqtt_topic","wkpbridge");
  prefs.end();
}
void saveSettings(){
  prefs.begin("wkpbridge",false);
  prefs.putString("wifi_ssid",settings.wifiSsid);prefs.putString("wifi_psk", settings.wifiPsk);
  prefs.putString("ble_addr", settings.bleAddress);prefs.putString("ble_atype",settings.bleAddrType);
  prefs.putString("ble_name", settings.bleName);  prefs.putString("svc_uuid", settings.serviceUuid);
  prefs.putString("wr_uuid",  settings.writeUuid); prefs.putString("nt_uuid",  settings.notifyUuid);
  prefs.putBool("auto_conn",settings.autoConnect);prefs.putBool("wr_rsp",settings.writeWithResponse);
  prefs.putUChar("scan_sec",settings.scanSeconds);
  prefs.putString("mqtt_host",settings.mqttHost);prefs.putUShort("mqtt_port",settings.mqttPort);
  prefs.putString("mqtt_user",settings.mqttUser);prefs.putString("mqtt_pass",settings.mqttPass);
  prefs.putString("mqtt_topic",settings.mqttTopic);
  prefs.end();addLog("Settings saved");
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
  if(settings.wifiPsk.isEmpty()) settings.wifiPsk=MYPSK;
  addLog("WiFi begin SSID="+settings.wifiSsid);
  WiFi.begin(settings.wifiSsid.c_str(),settings.wifiPsk.c_str());
  WiFi.setTxPower(WIFI_POWER_15dBm);lastWifiTryMs=millis();
}
void ensureMDNSOTA(){
  if(WiFi.status()!=WL_CONNECTED)return;
  if(!mdnsReady){if(MDNS.begin(HOSTNAME)){MDNS.addService("http","tcp",80);mdnsReady=true;addLog("mDNS: http://"+String(HOSTNAME)+".local/");}else addLog("mDNS failed");}
  if(!otaReady){ArduinoOTA.setHostname(HOSTNAME);ArduinoOTA.onStart([](){addLog("OTA start");});ArduinoOTA.onEnd([](){addLog("OTA end");});ArduinoOTA.onError([](ota_error_t e){addLog("OTA error "+String((int)e));});ArduinoOTA.begin();otaReady=true;addLog("OTA ready");}
}
void mqttPublish(const String &p){if(settings.mqttHost.isEmpty())return;addLog("MQTT(stub): "+p);}
void serviceMQTT(){}

// --------------------------------------------------------------------------
// BLE callbacks
// --------------------------------------------------------------------------
class ClientCB : public NimBLEClientCallbacks {
public:
  void onConnect(NimBLEClient *c) override {
    addLog("BLE onConnect: "+String(c->getPeerAddress().toString().c_str()));
    esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
  }
  void onConnectFail(NimBLEClient *c, int reason) override {
    // reason here is the raw HCI status code (not ble_hs wrapped)
    // Common HCI statuses: 0x3B=connection rejected due to limited resources,
    // 0x05=auth failure, 0x3A=controller busy, 0x02=unknown conn ID
    addLog("BLE onConnectFail HCI=0x"+String(reason,HEX)
           +" nimble=0x"+String(c->getLastError(),HEX)
           +" ("+String(nimbleErrStr(c->getLastError()))+")");
  }
  void onDisconnect(NimBLEClient *c, int reason) override {
    (void)c;writeChr=nullptr;notifyChr=nullptr;
    addLog("BLE onDisconnect reason=0x"+String(reason,HEX));
    esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
  }
  void onAuthenticationComplete(NimBLEConnInfo &i) override {
    addLog("BLE auth: enc="+String(i.isEncrypted())+" bonded="+String(i.isBonded())+" auth="+String(i.isAuthenticated()));
  }
};
ClientCB gClientCB;

void notifyCB(NimBLERemoteCharacteristic *c,uint8_t *d,size_t l,bool n){
  (void)c;(void)n;lastRxHex=bytesToHex(d,l);addLog("RX: "+lastRxHex);mqttPublish(lastRxHex);
}
void deleteBleClient(){
  if(bleClient){if(bleClient->isConnected())bleClient->disconnect();NimBLEDevice::deleteClient(bleClient);bleClient=nullptr;}
  writeChr=nullptr;notifyChr=nullptr;
}
bool isBleReady(){return bleClient&&bleClient->isConnected()&&writeChr;}

// --------------------------------------------------------------------------
// Parse and log Wyze manufacturer data
// Wyze mfr data layout (after 2-byte company ID 0x4459):
//   [0-1] = company ID (0x59, 0x44)
//   [2]   = data type?
//   [3]   = length?
//   [4-9] = MAC address (reversed)
//   [10]  = gateway type (0x07 = KP-01)
//   [11]  = pairing status (0x0A = paired, 0x00 = unpaired)
//   [12]  = lock status?
// --------------------------------------------------------------------------
void logWyzeMfrData(const NimBLEAdvertisedDevice *dev) {
  if(!dev->haveManufacturerData()) return;
  const std::string &m = dev->getManufacturerData();
  size_t len = m.size();
  String hex;
  for(size_t i=0;i<len;i++){
    const char *h="0123456789ABCDEF";
    hex += h[((uint8_t)m[i]>>4)&0xF];
    hex += h[(uint8_t)m[i]&0xF];
    if(i+1<len) hex+=' ';
  }
  addLog("  Wyze mfr data ("+String(len)+" bytes): "+hex);
  if(len > 11) {
    uint8_t devType    = (uint8_t)m[10];
    uint8_t pairStatus = (uint8_t)m[11];
    addLog("  -> devType=0x"+String(devType,HEX)
           +" pairStatus=0x"+String(pairStatus,HEX)
           +" ("+String(pairStatus==0x0A?"PAIRED":pairStatus==0x00?"UNPAIRED":"UNKNOWN")+")");
  }
  if(len > 12) {
    addLog("  -> byte[12]=0x"+String((uint8_t)m[12],HEX));
  }
}

bool isWyzeDevice(const NimBLEAdvertisedDevice *dev){
  if(!dev->haveManufacturerData())return false;
  const std::string &m=dev->getManufacturerData();
  if(m.size()<2)return false;
  return ((uint8_t)m[0]|((uint8_t)m[1]<<8))==WYZE_COMPANY_ID;
}

// --------------------------------------------------------------------------
// BLE scan
// --------------------------------------------------------------------------
bool doScanFindTarget(uint8_t secs,const String &targetUpper){
  if(scanRunning){addLog("Scan busy");return false;}
  scanRunning=true;gFoundValid=false;
  esp_coex_preference_set(ESP_COEX_PREFER_BT);
  addLog("Coex -> BLE priority");

  NimBLEScan *scan=NimBLEDevice::getScan();
  scan->setActiveScan(true);
  scan->setInterval(40);scan->setWindow(40);scan->setDuplicateFilter(false);

  addLog("BLE scan "+String(secs)+"s");
  NimBLEScanResults results=scan->getResults((uint32_t)secs*1000,false);
  addLog("Scan done: "+String(results.getCount())+" device(s)");

  String json="[";bool first=true;bool found=false;
  currentTargetAddr="";

  for(int i=0;i<results.getCount();i++){
    const NimBLEAdvertisedDevice *dev=results.getDevice(i);
    NimBLEAddress addr=dev->getAddress();
    String addrStr=String(addr.toString().c_str());
    String addrUp=addrStr;addrUp.toUpperCase();
    String name=dev->haveName()?String(dev->getName().c_str()):"";
    int rssi=dev->getRSSI();
    uint8_t at=addr.getType();
    String ats=(at==BLE_ADDR_RANDOM)?"random":"public";
    bool wyze=isWyzeDevice(dev);
    const uint8_t *rawBytes=addr.getBase()->val;

    addLog("  "+addrUp+" type="+String(at)+" ["+ats+"] '"+name+"' rssi="+String(rssi)+(wyze?" [Wyze]":"")+" raw="+bytesToHex(rawBytes,6));

    // Dump full Wyze manufacturer data for analysis
    if(wyze) logWyzeMfrData(dev);

    if(!first)json+=",";first=false;
    json+="{\"addr\":\""+jsonEscape(addrStr)+"\",\"addrType\":\""+ats+"\",\"name\":\""+jsonEscape(name)+"\",\"rssi\":"+String(rssi)+",\"wyze\":"+String(wyze?"true":"false")+"}";

    bool addrMatch=!targetUpper.isEmpty()&&addrUp==targetUpper;
    bool nameMatch=!found&&settings.bleName.length()&&name.length()&&[&](){
      String n1=name;n1.toLowerCase();String n2=settings.bleName;n2.toLowerCase();return n1.indexOf(n2)>=0;
    }();

    if(!found&&(addrMatch||nameMatch||(wyze&&!found))){
      memcpy(gFoundAddrBytes,rawBytes,6);
      gFoundAddrType=at;found=true;
      String reason=addrMatch?"addr":nameMatch?"name":"wyze-mfr";
      addLog("  -> "+reason+" match | saved bytes="+bytesToHex(gFoundAddrBytes,6)+" type="+String(at));
      if(!addrMatch)currentTargetAddr=addrStr;
    }
  }
  json+="]";lastScanJson=json;

  scan->stop();scan->clearResults();
  addLog("Scan stopped+cleared");
  scanRunning=false;
  if(found)gFoundValid=true;
  return found;
}

String scanJson(){
  String t=settings.bleAddress;t.trim();t.toUpperCase();
  doScanFindTarget(settings.scanSeconds,t);
  esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
  addLog("Coex -> balanced");
  return lastScanJson;
}

// --------------------------------------------------------------------------
// BLE connect
// --------------------------------------------------------------------------
bool tryConnect(const NimBLEAddress &addr,const char *label){
  bleClient=NimBLEDevice::createClient();
  bleClient->setClientCallbacks(&gClientCB,false);
  bleClient->setConnectionParams(24,40,0,400);
  bleClient->setConnectTimeout(10);
  addLog(String(label)+": connecting to "+String(addr.toString().c_str())+" type="+String(addr.getType()));
  bool ok=bleClient->connect(addr,false);
  int le=bleClient->getLastError();
  addLog(String(label)+": connect="+String(ok?"OK":"FAIL")+" lastErr=0x"+String(le,HEX)+" ("+nimbleErrStr(le)+")");
  return ok;
}

bool connectBle(){
  deleteBleClient();
  String target=settings.bleAddress;target.trim();target.toUpperCase();
  if(settings.serviceUuid.isEmpty()||settings.writeUuid.isEmpty()){addLog("Connect skipped: UUIDs not set");return false;}
  if(target.isEmpty()&&settings.bleName.isEmpty()){addLog("Connect skipped: no target");return false;}

  bool found=doScanFindTarget(settings.scanSeconds,target);
  if(!found||!gFoundValid){addLog("Target not found");esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);return false;}

  addLog("Pre-connect: saved bytes="+bytesToHex(gFoundAddrBytes,6)+" type="+String(gFoundAddrType)+" ("+String(gFoundAddrType==BLE_ADDR_RANDOM?"random":"public")+")");

  String typeStr=(gFoundAddrType==BLE_ADDR_RANDOM)?"random":"public";
  if(settings.bleAddrType!=typeStr){settings.bleAddrType=typeStr;saveSettings();addLog("addrType corrected to "+typeStr);}

  delay(100);
  esp_coex_preference_set(ESP_COEX_PREFER_BT);

  ble_addr_t bleAddr;bleAddr.type=gFoundAddrType;memcpy(bleAddr.val,gFoundAddrBytes,6);
  NimBLEAddress peerAddr(bleAddr);
  addLog("Attempt 1: NimBLEAddress from ble_addr_t -> "+String(peerAddr.toString().c_str())+" type="+String(peerAddr.getType()));

  bool ok=tryConnect(peerAddr,"Attempt1");
  if(!ok){
    deleteBleClient();delay(200);
    char addrStr[18];
    snprintf(addrStr,sizeof(addrStr),"%02x:%02x:%02x:%02x:%02x:%02x",
             gFoundAddrBytes[5],gFoundAddrBytes[4],gFoundAddrBytes[3],
             gFoundAddrBytes[2],gFoundAddrBytes[1],gFoundAddrBytes[0]);
    addLog("Attempt 2: string addr="+String(addrStr)+" type="+String(gFoundAddrType));
    NimBLEAddress fallback(addrStr,gFoundAddrType);
    addLog("Attempt 2: NimBLEAddress -> "+String(fallback.toString().c_str())+" type="+String(fallback.getType()));
    ok=tryConnect(fallback,"Attempt2");
  }

  if(!ok){deleteBleClient();esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);return false;}

  addLog("Link up!");
  bleClient->exchangeMTU();
  addLog("MTU="+String(bleClient->getMTU()));
  bleClient->updateConnParams(12,12,0,200);

  addLog("Discovering services...");
  NimBLERemoteService *svc=bleClient->getService(NimBLEUUID(settings.serviceUuid.c_str()));
  if(!svc){
    addLog("Service not found: "+settings.serviceUuid);
    const std::vector<NimBLERemoteService*>&svcs=bleClient->getServices(true);
    for(NimBLERemoteService *s:svcs)addLog("  Avail: "+String(s->getUUID().toString().c_str()));
    deleteBleClient();esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);return false;
  }
  addLog("Service found");

  writeChr=svc->getCharacteristic(NimBLEUUID(settings.writeUuid.c_str()));
  if(!writeChr){addLog("Write chr not found");deleteBleClient();esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);return false;}
  addLog("Write chr ok canWrite="+String((writeChr->canWrite()||writeChr->canWriteNoResponse())?"yes":"no"));

  if(settings.notifyUuid.length()){
    notifyChr=svc->getCharacteristic(NimBLEUUID(settings.notifyUuid.c_str()));
    if(notifyChr&&(notifyChr->canNotify()||notifyChr->canIndicate())){
      if(notifyChr->subscribe(true,notifyCB))addLog("Notify subscribed");
      else addLog("Notify subscribe failed");
    }else addLog("Notify chr not subscribable");
  }

  esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
  addLog("BLE ready");
  return true;
}

void disconnectBle(){deleteBleClient();esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);addLog("BLE disconnected");}

bool sendPacket(const uint8_t *d,size_t l,const char *tag){
  if(!isBleReady()){addLog(String("TX failed: ")+tag);return false;}
  lastTxHex=bytesToHex(d,l);addLog(String("TX ")+tag+": "+lastTxHex);
  bool ok=writeChr->writeValue(d,l,settings.writeWithResponse);
  addLog(String("TX ")+tag+": "+(ok?"OK":"FAIL"));return ok;
}
bool sendRawHex(const String &hex){
  std::vector<uint8_t> buf;
  if(!parseHexString(hex,buf)){addLog("Hex parse failed");return false;}
  return sendPacket(buf.data(),buf.size(),"RAW");
}

String makeStateJson(){
  String json;json.reserve(4096);
  String ip=WiFi.status()==WL_CONNECTED?WiFi.localIP().toString():"";
  String apIp=portalMode?WiFi.softAPIP().toString():"";
  String peer=(bleClient&&bleClient->isConnected())?String(bleClient->getPeerAddress().toString().c_str()):"";
  json+="{";
  json+="\"hostname\":\""+String(HOSTNAME)+"\",";
  json+="\"wifiConnected\":"+String(WiFi.status()==WL_CONNECTED?"true":"false")+",";
  json+="\"portalMode\":"+String(portalMode?"true":"false")+",";
  json+="\"ip\":\""+jsonEscape(ip)+"\",\"apIp\":\""+jsonEscape(apIp)+"\",";
  json+="\"ssid\":\""+jsonEscape(settings.wifiSsid)+"\",";
  json+="\"mac\":\""+jsonEscape(WiFi.macAddress())+"\",";
  json+="\"rssi\":"+String(WiFi.status()==WL_CONNECTED?WiFi.RSSI():0)+",";
  json+="\"bleConnected\":"+String(isBleReady()?"true":"false")+",";
  json+="\"blePeer\":\""+jsonEscape(peer)+"\",";
  json+="\"bleAddress\":\""+jsonEscape(settings.bleAddress)+"\",";
  json+="\"bleAddrType\":\""+jsonEscape(settings.bleAddrType)+"\",";
  json+="\"bleName\":\""+jsonEscape(settings.bleName)+"\",";
  json+="\"serviceUuid\":\""+jsonEscape(settings.serviceUuid)+"\",";
  json+="\"writeUuid\":\""+jsonEscape(settings.writeUuid)+"\",";
  json+="\"writeWithResponse\":"+String(settings.writeWithResponse?"true":"false")+",";
  json+="\"notifyUuid\":\""+jsonEscape(settings.notifyUuid)+"\",";
  json+="\"autoConnect\":"+String(settings.autoConnect?"true":"false")+",";
  json+="\"scanSeconds\":"+String(settings.scanSeconds)+",";
  json+="\"mqttHost\":\""+jsonEscape(settings.mqttHost)+"\",\"mqttPort\":"+String(settings.mqttPort)+",";
  json+="\"mqttUser\":\""+jsonEscape(settings.mqttUser)+"\",\"mqttTopic\":\""+jsonEscape(settings.mqttTopic)+"\",";
  json+="\"lastTx\":\""+jsonEscape(lastTxHex)+"\",\"lastRx\":\""+jsonEscape(lastRxHex)+"\",";
  json+="\"logs\":\""+jsonEscape(logBuffer)+"\",\"scan\":"+lastScanJson;
  json+="}";return json;
}

void sendOk(const String &m){server.send(200,"application/json","{\"ok\":true,\"msg\":\""+jsonEscape(m)+"\"}");}
void sendErr(const String &m){server.send(200,"application/json","{\"ok\":false,\"msg\":\""+jsonEscape(m)+"\"}");}
bool argBool(const char *n,bool d){if(!server.hasArg(n))return d;String v=server.arg(n);v.toLowerCase();return v=="1"||v=="true"||v=="on"||v=="yes";}
void handleRoot()  {server.send_P(200,"text/html",INDEX_HTML);}
void handleState() {server.send(200,"application/json",makeStateJson());}
void handleScan()  {server.send(200,"application/json",scanJson());}
void handleSaveConfig(){
  settings.bleAddress  =server.arg("bleAddress");  settings.bleAddress.trim();
  settings.bleAddrType =server.arg("bleAddrType"); if(settings.bleAddrType!="random")settings.bleAddrType="public";
  settings.bleName     =server.arg("bleName");
  settings.serviceUuid =server.arg("serviceUuid"); settings.serviceUuid.trim();
  settings.writeUuid   =server.arg("writeUuid");   settings.writeUuid.trim();
  settings.notifyUuid  =server.arg("notifyUuid");  settings.notifyUuid.trim();
  settings.autoConnect      =argBool("autoConnect",      settings.autoConnect);
  settings.writeWithResponse=argBool("writeWithResponse",settings.writeWithResponse);
  if(server.hasArg("scanSeconds")){int v=server.arg("scanSeconds").toInt();if(v<1)v=1;if(v>20)v=20;settings.scanSeconds=(uint8_t)v;}
  if(server.hasArg("mqttHost")) settings.mqttHost =server.arg("mqttHost");
  if(server.hasArg("mqttPort")) settings.mqttPort =(uint16_t)server.arg("mqttPort").toInt();
  if(server.hasArg("mqttUser")) settings.mqttUser =server.arg("mqttUser");
  if(server.hasArg("mqttPass")) settings.mqttPass =server.arg("mqttPass");
  if(server.hasArg("mqttTopic"))settings.mqttTopic=server.arg("mqttTopic");
  saveSettings();sendOk("Config saved");
}
void handleSaveWifi(){settings.wifiSsid=server.arg("ssid");settings.wifiPsk=server.arg("psk");saveSettings();beginWiFi(portalMode);sendOk("WiFi saved");}
void handleClearBonds(){NimBLEDevice::deleteAllBonds();addLog("Bonds cleared");sendOk("Bonds cleared");}
void handleConnect()   {connectBle()  ?sendOk("BLE connected"):sendErr("Failed - check log");}
void handleDisconnect(){disconnectBle();sendOk("Disconnected");}
void handleSendFF()    {sendPacket(PKT_FF,sizeof(PKT_FF),"FF")?sendOk("FF sent"):sendErr("FF failed");}
void handleSendFE()    {sendPacket(PKT_FE,sizeof(PKT_FE),"FE")?sendOk("FE sent"):sendErr("FE failed");}
void handleSendRaw()   {sendRawHex(server.arg("hex"))?sendOk("Raw sent"):sendErr("Raw failed");}
void handleClearLog()  {logBuffer="";lastTxHex="";lastRxHex="";sendOk("Log cleared");}
void handleReboot()    {sendOk("Rebooting");delay(200);ESP.restart();}

void setupWeb(){
  server.on("/",HTTP_GET,handleRoot);server.on("/api/state",HTTP_GET,handleState);
  server.on("/api/scan",HTTP_GET,handleScan);
  server.on("/api/saveConfig",HTTP_POST,handleSaveConfig);server.on("/api/saveWifi",HTTP_POST,handleSaveWifi);
  server.on("/api/connect",HTTP_POST,handleConnect);      server.on("/api/disconnect",HTTP_POST,handleDisconnect);
  server.on("/api/sendFF",HTTP_POST,handleSendFF);        server.on("/api/sendFE",HTTP_POST,handleSendFE);
  server.on("/api/sendRaw",HTTP_POST,handleSendRaw);      server.on("/api/clearLog",HTTP_POST,handleClearLog);
  server.on("/api/clearBonds",HTTP_POST,handleClearBonds);server.on("/api/reboot",HTTP_POST,handleReboot);
  server.onNotFound([](){if(portalMode){server.sendHeader("Location","/",true);server.send(302,"text/plain","");}else server.send(404,"text/plain","Not found");});
  server.begin();addLog("HTTP server started");
}

void serviceWiFi(){
  bool up=(WiFi.status()==WL_CONNECTED);
  if(up&&!wifiWasConnected){wifiWasConnected=true;addLog("WiFi up: "+WiFi.localIP().toString());ensureMDNSOTA();stopPortal();}
  if(!up&&wifiWasConnected){wifiWasConnected=false;addLog("WiFi down");lastWifiTryMs=millis();}
  if(!up){if(millis()-lastWifiTryMs>15000)beginWiFi(portalMode);if(!portalMode&&millis()>30000&&millis()-lastWifiTryMs>10000)startPortal();}
}
void serviceBleAutoConnect(){
  if(!settings.autoConnect||scanRunning||isBleReady())return;
  if(settings.serviceUuid.isEmpty()||settings.writeUuid.isEmpty())return;
  if(millis()-lastBleTryMs<20000)return;
  lastBleTryMs=millis();addLog("BLE auto-connect");connectBle();
}

void setup(){
  DBG_BEGIN(115200);delay(200);addLog("Boot");
  loadSettings();
  addLog("addr="+settings.bleAddress+" storedType="+settings.bleAddrType);
  addLog("svc="+settings.serviceUuid+" wr="+settings.writeUuid);
  WiFi.disconnect(true,true);delay(200);
  beginWiFi(false);
  NimBLEDevice::init("");
  NimBLEDevice::setPower(9);
  NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_RANDOM);
  addLog("Own addr: "+String(NimBLEDevice::getAddress().toString().c_str()));
  NimBLEDevice::setSecurityAuth(0);
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_NO_INPUT_OUTPUT);
  esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
  addLog("NimBLE init done");
  setupWeb();
  unsigned long t0=millis();
  while(WiFi.status()!=WL_CONNECTED&&millis()-t0<12000){delay(100);server.handleClient();}
  if(WiFi.status()!=WL_CONNECTED){addLog("WiFi timeout, portal");startPortal();}
  else ensureMDNSOTA();
}

void loop(){
  server.handleClient();
  if(portalMode)dns.processNextRequest();
  if(otaReady&&WiFi.status()==WL_CONNECTED)ArduinoOTA.handle();
  serviceWiFi();serviceMQTT();serviceBleAutoConnect();
  if(millis()-lastStateMs>10000){
    lastStateMs=millis();
    addLog("State wifi="+String(WiFi.status()==WL_CONNECTED?"up":"down")+" ble="+String(isBleReady()?"up":"down"));
  }
  delay(5);
}
