// WKPbridge.ino
// ESP32-C3 BLE-to-WiFi bridge for Wyze Wireless Keypad (WLCKKP1)
//
// Fixes applied 2026-03-24:
//  1. Security set to NO-BOND / NO-PAIRING  (nRF Connect shows "NOT BONDED" on successful connect)
//  2. secureConnection() call removed        (device does not encrypt)
//  3. BLE coex priority raised BEFORE connect() not just during scan
//  4. Default UUIDs pre-set to Nordic UART Service (confirmed by nRF Connect screenshot)
//  5. Manufacturer-data fallback scan match on Wyze Company ID 0x4459
//  6. connect() args corrected: deleteAttrs=false so attr cache is preserved

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

// Nordic UART Service UUIDs (confirmed via nRF Connect on WLCKKP1)
static const char *NUS_SERVICE_UUID = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
static const char *NUS_RX_UUID      = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"; // write (phone->device)
static const char *NUS_TX_UUID      = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"; // notify (device->phone)

// Wyze manufacturer company ID seen in advertisement
static const uint16_t WYZE_COMPANY_ID = 0x4459;

#if DEBUG_SERIAL
  #define DBG_BEGIN(x)    Serial.begin(x)
  #define DBG_PRINTLN(x)  Serial.println(x)
#else
  #define DBG_BEGIN(x)
  #define DBG_PRINTLN(x)
#endif

// --------------------------------------------------------------------------
// Settings
// --------------------------------------------------------------------------
struct Settings {
  String  wifiSsid;
  String  wifiPsk;
  String  bleAddress;
  String  bleAddrType;
  String  bleName;
  String  serviceUuid;
  String  writeUuid;
  String  notifyUuid;
  bool    autoConnect       = false;
  bool    writeWithResponse = false;
  uint8_t scanSeconds       = 5;
  String  mqttHost;
  uint16_t mqttPort         = 1883;
  String  mqttUser;
  String  mqttPass;
  String  mqttTopic;
};

Preferences prefs;
WebServer   server(80);
DNSServer   dns;
Settings    settings;

bool portalMode       = false;
bool wifiWasConnected = false;
bool otaReady         = false;
bool mdnsReady        = false;
bool scanRunning      = false;

unsigned long lastWifiTryMs = 0;
unsigned long lastBleTryMs  = 0;
unsigned long lastStateMs   = 0;

String logBuffer;
String lastScanJson = "[]";
String lastTxHex;
String lastRxHex;
String currentTargetAddr;

NimBLEClient               *bleClient = nullptr;
NimBLERemoteCharacteristic *writeChr  = nullptr;
NimBLERemoteCharacteristic *notifyChr = nullptr;

static const uint8_t PKT_FF[8] = {0xDE,0xC0,0xAD,0xDE,0xFF,0x01,0x1E,0xF1};
static const uint8_t PKT_FE[8] = {0xDE,0xC0,0xAD,0xDE,0xFE,0x01,0x1E,0xF1};

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------
String jsonEscape(const String &in) {
  String out; out.reserve(in.length() + 16);
  for (size_t i = 0; i < in.length(); i++) {
    char c = in[i];
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '"':  out += "\\\""; break;
      case '\n': out += "\\n";  break;
      case '\r': break;
      case '\t': out += "\\t";  break;
      default: if((uint8_t)c<32) out+=' '; else out+=c; break;
    }
  }
  return out;
}

void addLog(const String &line) {
  String s = String(millis()) + " | " + line;
  logBuffer += s + "\n";
  if (logBuffer.length() > 14000) logBuffer.remove(0, logBuffer.length() - 14000);
  DBG_PRINTLN(s);
}

String bytesToHex(const uint8_t *data, size_t len) {
  const char *hc = "0123456789ABCDEF";
  String out; out.reserve(len * 3);
  for (size_t i = 0; i < len; i++) {
    out += hc[(data[i]>>4)&0x0F]; out += hc[data[i]&0x0F];
    if (i+1<len) out += ' ';
  }
  return out;
}

bool parseHexString(String s, std::vector<uint8_t> &out) {
  out.clear();
  s.replace("0x",""); s.replace("0X","");
  s.replace(","," "); s.replace(":"," "); s.replace("-"," ");
  while (s.indexOf("  ")>=0) s.replace("  "," ");
  s.trim(); if(s.isEmpty()) return false;
  int start=0;
  while(start<(int)s.length()){
    while(start<(int)s.length()&&s[start]==' ') start++;
    if(start>=(int)s.length()) break;
    int end=s.indexOf(' ',start); if(end<0) end=s.length();
    String tok=s.substring(start,end); tok.trim();
    if(tok.isEmpty()){start=end+1;continue;}
    if(tok.length()>2) return false;
    char *ep=nullptr; long v=strtol(tok.c_str(),&ep,16);
    if(!ep||*ep!=0||v<0||v>255) return false;
    out.push_back((uint8_t)v); start=end+1;
  }
  return !out.empty();
}

// --------------------------------------------------------------------------
// Settings persistence
// --------------------------------------------------------------------------
void loadSettings() {
  prefs.begin("wkpbridge", true);
  settings.wifiSsid          = prefs.getString("wifi_ssid",  MYSSID);
  settings.wifiPsk           = prefs.getString("wifi_psk",   MYPSK);
  settings.bleAddress        = prefs.getString("ble_addr",   "");
  settings.bleAddrType       = prefs.getString("ble_atype",  "random");
  settings.bleName           = prefs.getString("ble_name",   "Wyze Lock");
  settings.serviceUuid       = prefs.getString("svc_uuid",   NUS_SERVICE_UUID);
  settings.writeUuid         = prefs.getString("wr_uuid",    NUS_RX_UUID);
  settings.notifyUuid        = prefs.getString("nt_uuid",    NUS_TX_UUID);
  settings.autoConnect       = prefs.getBool  ("auto_conn",  false);
  settings.writeWithResponse = prefs.getBool  ("wr_rsp",     false);
  settings.scanSeconds       = prefs.getUChar ("scan_sec",   5);
  settings.mqttHost          = prefs.getString("mqtt_host",  "");
  settings.mqttPort          = prefs.getUShort("mqtt_port",  1883);
  settings.mqttUser          = prefs.getString("mqtt_user",  "");
  settings.mqttPass          = prefs.getString("mqtt_pass",  "");
  settings.mqttTopic         = prefs.getString("mqtt_topic", "wkpbridge");
  prefs.end();
}

void saveSettings() {
  prefs.begin("wkpbridge", false);
  prefs.putString("wifi_ssid",  settings.wifiSsid);
  prefs.putString("wifi_psk",   settings.wifiPsk);
  prefs.putString("ble_addr",   settings.bleAddress);
  prefs.putString("ble_atype",  settings.bleAddrType);
  prefs.putString("ble_name",   settings.bleName);
  prefs.putString("svc_uuid",   settings.serviceUuid);
  prefs.putString("wr_uuid",    settings.writeUuid);
  prefs.putString("nt_uuid",    settings.notifyUuid);
  prefs.putBool  ("auto_conn",  settings.autoConnect);
  prefs.putBool  ("wr_rsp",     settings.writeWithResponse);
  prefs.putUChar ("scan_sec",   settings.scanSeconds);
  prefs.putString("mqtt_host",  settings.mqttHost);
  prefs.putUShort("mqtt_port",  settings.mqttPort);
  prefs.putString("mqtt_user",  settings.mqttUser);
  prefs.putString("mqtt_pass",  settings.mqttPass);
  prefs.putString("mqtt_topic", settings.mqttTopic);
  prefs.end();
  addLog("Settings saved");
}

// --------------------------------------------------------------------------
// WiFi
// --------------------------------------------------------------------------
void startPortal() {
  if(portalMode) return;
  WiFi.mode(WIFI_AP_STA); WiFi.softAP(AP_SSID);
  dns.start(DNS_PORT,"*",WiFi.softAPIP()); portalMode=true;
  addLog("Portal: "+String(AP_SSID)+" "+WiFi.softAPIP().toString());
}
void stopPortal() {
  if(!portalMode) return;
  dns.stop(); WiFi.softAPdisconnect(true); portalMode=false; addLog("Portal stopped");
}
void beginWiFi(bool keepAp) {
  WiFi.persistent(false); WiFi.setAutoReconnect(true);
  WiFi.mode(keepAp?WIFI_AP_STA:WIFI_STA); WiFi.setHostname(HOSTNAME);
  if(settings.wifiSsid.isEmpty()) settings.wifiSsid=MYSSID;
  if(settings.wifiPsk.isEmpty())  settings.wifiPsk=MYPSK;
  addLog("WiFi begin SSID="+settings.wifiSsid);
  WiFi.begin(settings.wifiSsid.c_str(),settings.wifiPsk.c_str());
  WiFi.setTxPower(WIFI_POWER_15dBm); lastWifiTryMs=millis();
}
void ensureMDNSOTA() {
  if(WiFi.status()!=WL_CONNECTED) return;
  if(!mdnsReady){
    if(MDNS.begin(HOSTNAME)){ MDNS.addService("http","tcp",80); mdnsReady=true; addLog("mDNS: http://"+String(HOSTNAME)+".local/"); }
    else addLog("mDNS failed");
  }
  if(!otaReady){
    ArduinoOTA.setHostname(HOSTNAME);
    ArduinoOTA.onStart([](){addLog("OTA start");});
    ArduinoOTA.onEnd([](){addLog("OTA end");});
    ArduinoOTA.onError([](ota_error_t e){addLog("OTA error "+String((int)e));});
    ArduinoOTA.begin(); otaReady=true; addLog("OTA ready");
  }
}

// --------------------------------------------------------------------------
// MQTT stub
// --------------------------------------------------------------------------
void mqttPublish(const String &payload) {
  if(settings.mqttHost.isEmpty()) return;
  addLog("MQTT (stub): "+payload);
}
void serviceMQTT() { }

// --------------------------------------------------------------------------
// BLE client callbacks
// NOTE: No security/bonding callbacks needed - WLCKKP1 connects unencrypted
// --------------------------------------------------------------------------
class ClientCB : public NimBLEClientCallbacks {
public:
  void onConnect(NimBLEClient *c) override {
    addLog("BLE onConnect: "+String(c->getPeerAddress().toString().c_str()));
    esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
  }
  void onConnectFail(NimBLEClient *c, int reason) override {
    addLog("BLE onConnectFail: reason=0x"+String(reason, HEX)+" lastErr=0x"+String(c->getLastError(), HEX));
  }
  void onDisconnect(NimBLEClient *c, int reason) override {
    (void)c; writeChr=nullptr; notifyChr=nullptr;
    addLog("BLE onDisconnect: reason=0x"+String(reason, HEX));
    esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
  }
  // Auth callbacks kept for logging only - we do not initiate pairing
  void onAuthenticationComplete(NimBLEConnInfo &connInfo) override {
    addLog("BLE auth complete: encrypted="+String(connInfo.isEncrypted())
           +" bonded="+String(connInfo.isBonded())
           +" authenticated="+String(connInfo.isAuthenticated()));
  }
};
ClientCB gClientCB;

void notifyCB(NimBLERemoteCharacteristic *pChr, uint8_t *data, size_t len, bool isNotify) {
  (void)pChr; (void)isNotify;
  lastRxHex=bytesToHex(data,len); addLog("RX: "+lastRxHex); mqttPublish(lastRxHex);
}
void deleteBleClient() {
  if(bleClient){ if(bleClient->isConnected()) bleClient->disconnect(); NimBLEDevice::deleteClient(bleClient); bleClient=nullptr; }
  writeChr=nullptr; notifyChr=nullptr;
}
bool isBleReady() { return bleClient && bleClient->isConnected() && writeChr; }

// --------------------------------------------------------------------------
// Manufacturer data match helper - check for Wyze Company ID 0x4459
// --------------------------------------------------------------------------
bool isWyzeDevice(const NimBLEAdvertisedDevice *dev) {
  if (!dev->haveManufacturerData()) return false;
  const std::string &mfr = dev->getManufacturerData();
  if (mfr.size() < 2) return false;
  uint16_t companyId = (uint8_t)mfr[0] | ((uint8_t)mfr[1] << 8);
  return companyId == WYZE_COMPANY_ID;
}

// --------------------------------------------------------------------------
// BLE scan
// --------------------------------------------------------------------------
const NimBLEAdvertisedDevice* doScanFindTarget(uint8_t secs, const String &targetUpper) {
  if(scanRunning){ addLog("Scan busy"); return nullptr; }
  scanRunning=true;

  esp_coex_preference_set(ESP_COEX_PREFER_BT);
  addLog("Coex -> BLE priority");

  NimBLEScan *scan = NimBLEDevice::getScan();
  scan->setActiveScan(true);
  scan->setInterval(40);
  scan->setWindow(40);
  scan->setDuplicateFilter(false);

  uint32_t durationMs = (uint32_t)secs * 1000;
  addLog("BLE scan "+String(secs)+"s ("+String(durationMs)+"ms)");
  NimBLEScanResults results = scan->getResults(durationMs, false);
  addLog("Scan done: "+String(results.getCount())+" device(s)");

  const NimBLEAdvertisedDevice *found = nullptr;
  String json="["; bool first=true;
  currentTargetAddr="";

  for(int i=0;i<results.getCount();i++){
    const NimBLEAdvertisedDevice *dev = results.getDevice(i);
    String addr  = String(dev->getAddress().toString().c_str());
    String addrUp = addr; addrUp.toUpperCase();
    String name  = dev->haveName()?String(dev->getName().c_str()):"";
    int rssi     = dev->getRSSI();
    uint8_t at   = dev->getAddress().getType();
    String ats   = (at==BLE_ADDR_RANDOM)?"random":"public";
    bool wyze    = isWyzeDevice(dev);
    addLog("  "+addrUp+" ["+ats+"] '"+name+"' rssi="+String(rssi)+(wyze?" [Wyze]":""));
    if(!first) json+=","; first=false;
    json+="{\"addr\":\""+jsonEscape(addr)+"\",\"addrType\":\""+ats+"\",\"name\":\""+jsonEscape(name)+"\",\"rssi\":"+String(rssi)+",\"wyze\":"+String(wyze?"true":"false")+"}";

    // Priority 1: exact address match
    if(!found&&!targetUpper.isEmpty()&&addrUp==targetUpper){ found=dev; addLog("  -> addr match"); }
    // Priority 2: name match
    if(!found&&settings.bleName.length()&&name.length()){
      String n1=name; n1.toLowerCase(); String n2=settings.bleName; n2.toLowerCase();
      if(n1.indexOf(n2)>=0){ found=dev; addLog("  -> name match '"+name+"'"); currentTargetAddr=addr; }
    }
    // Priority 3: Wyze manufacturer data fallback (Company ID 0x4459)
    if(!found&&wyze){ found=dev; addLog("  -> Wyze mfr-data match"); currentTargetAddr=addr; }
  }
  json+="]"; lastScanJson=json;
  scanRunning=false;
  return found;
}

String scanJson() {
  String t=settings.bleAddress; t.trim(); t.toUpperCase();
  doScanFindTarget(settings.scanSeconds, t);
  esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
  addLog("Coex -> balanced");
  return lastScanJson;
}

// --------------------------------------------------------------------------
// BLE connect
// FIX: Wyze keypad connects WITHOUT bonding/encryption (confirmed by nRF Connect).
//      - Removed BLE_SM_PAIR_AUTHREQ_BOND from security flags in setup()
//      - Removed secureConnection() call here
//      - Raised BLE coex priority BEFORE connect(), not just during scan
//      - connect() called with deleteAttrs=false to preserve service cache
// --------------------------------------------------------------------------
bool connectBle() {
  deleteBleClient();
  String target=settings.bleAddress; target.trim(); target.toUpperCase();
  if(settings.serviceUuid.isEmpty()||settings.writeUuid.isEmpty()){
    addLog("Connect skipped: UUIDs not set"); return false;
  }
  if(target.isEmpty()&&settings.bleName.isEmpty()){
    addLog("Connect skipped: no target"); return false;
  }

  const NimBLEAdvertisedDevice *found=doScanFindTarget(settings.scanSeconds,target);
  if(!found){
    addLog("Target not found in scan");
    esp_coex_preference_set(ESP_COEX_PREFER_BALANCE); return false;
  }

  addLog("Connecting to "+String(found->getAddress().toString().c_str())
         +" addrType="+String(found->getAddress().getType()));

  // FIX: boost BLE coex priority for the connect window (WiFi was racing connect)
  esp_coex_preference_set(ESP_COEX_PREFER_BT);

  bleClient=NimBLEDevice::createClient();
  bleClient->setClientCallbacks(&gClientCB, false);
  bleClient->setConnectionParams(24, 40, 0, 400);
  bleClient->setConnectTimeout(10);  // 10s is plenty; 15s was causing timeout loops

  // FIX: pass deleteAttrs=false (was true) to keep attribute cache across reconnects
  if(!bleClient->connect(found, false, false, false)) {
    addLog("connect() failed lastErr=0x"+String(bleClient->getLastError(), HEX));
    deleteBleClient(); esp_coex_preference_set(ESP_COEX_PREFER_BALANCE); return false;
  }
  addLog("Link up — no pairing required (device connects unencrypted)");

  // FIX: Do NOT call secureConnection() - WLCKKP1 is NOT BONDED per nRF Connect observation
  // Calling it would cause a pairing attempt the device rejects, killing the link.

  bleClient->exchangeMTU();
  addLog("MTU="+String(bleClient->getMTU()));
  bleClient->updateConnParams(12, 12, 0, 200);

  addLog("Discovering services...");
  NimBLERemoteService *svc=bleClient->getService(NimBLEUUID(settings.serviceUuid.c_str()));
  if(!svc){
    addLog("Service not found: "+settings.serviceUuid);
    const std::vector<NimBLERemoteService*> &svcs=bleClient->getServices(true);
    for(NimBLERemoteService *s:svcs) addLog("  Avail: "+String(s->getUUID().toString().c_str()));
    deleteBleClient(); esp_coex_preference_set(ESP_COEX_PREFER_BALANCE); return false;
  }
  addLog("Service found");

  writeChr=svc->getCharacteristic(NimBLEUUID(settings.writeUuid.c_str()));
  if(!writeChr){
    addLog("Write chr not found"); deleteBleClient(); esp_coex_preference_set(ESP_COEX_PREFER_BALANCE); return false;
  }
  addLog("Write chr ok canWrite="+String((writeChr->canWrite()||writeChr->canWriteNoResponse())?"yes":"no"));

  if(settings.notifyUuid.length()){
    notifyChr=svc->getCharacteristic(NimBLEUUID(settings.notifyUuid.c_str()));
    if(notifyChr&&(notifyChr->canNotify()||notifyChr->canIndicate())){
      if(notifyChr->subscribe(true,notifyCB)) addLog("Notify subscribed");
      else addLog("Notify subscribe failed");
    } else addLog("Notify chr not subscribable");
  }

  esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
  addLog("BLE ready");
  return true;
}

void disconnectBle() {
  deleteBleClient(); esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
  addLog("BLE disconnected");
}

// --------------------------------------------------------------------------
// Send
// --------------------------------------------------------------------------
bool sendPacket(const uint8_t *data, size_t len, const char *tag) {
  if(!isBleReady()){ addLog(String("TX failed: ")+tag); return false; }
  lastTxHex=bytesToHex(data,len); addLog(String("TX ")+tag+": "+lastTxHex);
  bool ok=writeChr->writeValue(data,len,settings.writeWithResponse);
  addLog(String("TX ")+tag+": "+(ok?"OK":"FAIL")); return ok;
}
bool sendRawHex(const String &hex) {
  std::vector<uint8_t> buf;
  if(!parseHexString(hex,buf)){addLog("Hex parse failed");return false;}
  return sendPacket(buf.data(),buf.size(),"RAW");
}

// --------------------------------------------------------------------------
// State JSON
// --------------------------------------------------------------------------
String makeStateJson() {
  String json; json.reserve(4096);
  String ip=WiFi.status()==WL_CONNECTED?WiFi.localIP().toString():"";
  String apIp=portalMode?WiFi.softAPIP().toString():"";
  String peer=(bleClient&&bleClient->isConnected())?String(bleClient->getPeerAddress().toString().c_str()):"";
  json+="{";
  json+="\"hostname\":\""+String(HOSTNAME)+"\",";
  json+="\"wifiConnected\":"+String(WiFi.status()==WL_CONNECTED?"true":"false")+",";
  json+="\"portalMode\":"+String(portalMode?"true":"false")+",";
  json+="\"ip\":\""+jsonEscape(ip)+"\",";
  json+="\"apIp\":\""+jsonEscape(apIp)+"\",";
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
  json+="\"mqttHost\":\""+jsonEscape(settings.mqttHost)+"\",";
  json+="\"mqttPort\":"+String(settings.mqttPort)+",";
  json+="\"mqttUser\":\""+jsonEscape(settings.mqttUser)+"\",";
  json+="\"mqttTopic\":\""+jsonEscape(settings.mqttTopic)+"\",";
  json+="\"lastTx\":\""+jsonEscape(lastTxHex)+"\",";
  json+="\"lastRx\":\""+jsonEscape(lastRxHex)+"\",";
  json+="\"logs\":\""+jsonEscape(logBuffer)+"\",";
  json+="\"scan\":"+lastScanJson;
  json+="}"; return json;
}

// --------------------------------------------------------------------------
// Web handlers
// --------------------------------------------------------------------------
void sendOk(const String &m)  { server.send(200,"application/json","{\"ok\":true,\"msg\":\""+jsonEscape(m)+"\"}"); }
void sendErr(const String &m) { server.send(200,"application/json","{\"ok\":false,\"msg\":\""+jsonEscape(m)+"\"}"); }
bool argBool(const char *n, bool d){
  if(!server.hasArg(n)) return d; String v=server.arg(n); v.toLowerCase();
  return v=="1"||v=="true"||v=="on"||v=="yes";
}
void handleRoot()  { server.send_P(200,"text/html",INDEX_HTML); }
void handleState() { server.send(200,"application/json",makeStateJson()); }
void handleScan()  { server.send(200,"application/json",scanJson()); }
void handleSaveConfig(){
  settings.bleAddress  =server.arg("bleAddress");  settings.bleAddress.trim();
  settings.bleAddrType =server.arg("bleAddrType"); if(settings.bleAddrType!="random") settings.bleAddrType="public";
  settings.bleName     =server.arg("bleName");
  settings.serviceUuid =server.arg("serviceUuid"); settings.serviceUuid.trim();
  settings.writeUuid   =server.arg("writeUuid");   settings.writeUuid.trim();
  settings.notifyUuid  =server.arg("notifyUuid");  settings.notifyUuid.trim();
  settings.autoConnect      =argBool("autoConnect",      settings.autoConnect);
  settings.writeWithResponse=argBool("writeWithResponse",settings.writeWithResponse);
  if(server.hasArg("scanSeconds")){ int v=server.arg("scanSeconds").toInt(); if(v<1)v=1; if(v>20)v=20; settings.scanSeconds=(uint8_t)v; }
  if(server.hasArg("mqttHost"))  settings.mqttHost  =server.arg("mqttHost");
  if(server.hasArg("mqttPort"))  settings.mqttPort  =(uint16_t)server.arg("mqttPort").toInt();
  if(server.hasArg("mqttUser"))  settings.mqttUser  =server.arg("mqttUser");
  if(server.hasArg("mqttPass"))  settings.mqttPass  =server.arg("mqttPass");
  if(server.hasArg("mqttTopic")) settings.mqttTopic =server.arg("mqttTopic");
  saveSettings(); sendOk("Config saved");
}
void handleSaveWifi(){
  settings.wifiSsid=server.arg("ssid"); settings.wifiPsk=server.arg("psk");
  saveSettings(); beginWiFi(portalMode); sendOk("WiFi saved");
}
void handleClearBonds(){
  NimBLEDevice::deleteAllBonds();
  addLog("All BLE bonds cleared");
  sendOk("Bonds cleared");
}
void handleConnect()   { connectBle()  ?sendOk("BLE connected"):sendErr("Failed - check log"); }
void handleDisconnect(){ disconnectBle(); sendOk("Disconnected"); }
void handleSendFF()    { sendPacket(PKT_FF,sizeof(PKT_FF),"FF")?sendOk("FF sent"):sendErr("FF failed"); }
void handleSendFE()    { sendPacket(PKT_FE,sizeof(PKT_FE),"FE")?sendOk("FE sent"):sendErr("FE failed"); }
void handleSendRaw()   { sendRawHex(server.arg("hex"))?sendOk("Raw sent"):sendErr("Raw failed"); }
void handleClearLog()  { logBuffer=""; lastTxHex=""; lastRxHex=""; sendOk("Log cleared"); }
void handleReboot()    { sendOk("Rebooting"); delay(200); ESP.restart(); }

void setupWeb(){
  server.on("/",               HTTP_GET,  handleRoot);
  server.on("/api/state",      HTTP_GET,  handleState);
  server.on("/api/scan",       HTTP_GET,  handleScan);
  server.on("/api/saveConfig", HTTP_POST, handleSaveConfig);
  server.on("/api/saveWifi",   HTTP_POST, handleSaveWifi);
  server.on("/api/connect",    HTTP_POST, handleConnect);
  server.on("/api/disconnect", HTTP_POST, handleDisconnect);
  server.on("/api/sendFF",     HTTP_POST, handleSendFF);
  server.on("/api/sendFE",     HTTP_POST, handleSendFE);
  server.on("/api/sendRaw",    HTTP_POST, handleSendRaw);
  server.on("/api/clearLog",   HTTP_POST, handleClearLog);
  server.on("/api/clearBonds", HTTP_POST, handleClearBonds);
  server.on("/api/reboot",     HTTP_POST, handleReboot);
  server.onNotFound([](){
    if(portalMode){server.sendHeader("Location","/",true);server.send(302,"text/plain","");}
    else server.send(404,"text/plain","Not found");
  });
  server.begin(); addLog("HTTP server started");
}

// --------------------------------------------------------------------------
// Service loops
// --------------------------------------------------------------------------
void serviceWiFi(){
  bool up=(WiFi.status()==WL_CONNECTED);
  if(up&&!wifiWasConnected){wifiWasConnected=true;addLog("WiFi up: "+WiFi.localIP().toString());ensureMDNSOTA();stopPortal();}
  if(!up&&wifiWasConnected){wifiWasConnected=false;addLog("WiFi down");lastWifiTryMs=millis();}
  if(!up){
    if(millis()-lastWifiTryMs>15000) beginWiFi(portalMode);
    if(!portalMode&&millis()>30000&&millis()-lastWifiTryMs>10000) startPortal();
  }
}
void serviceBleAutoConnect(){
  if(!settings.autoConnect||scanRunning) return;
  if(isBleReady()) return;
  if(settings.serviceUuid.isEmpty()||settings.writeUuid.isEmpty()) return;
  if(millis()-lastBleTryMs<20000) return;
  lastBleTryMs=millis(); addLog("BLE auto-connect"); connectBle();
}

// --------------------------------------------------------------------------
// Setup / loop
// --------------------------------------------------------------------------
void setup(){
  DBG_BEGIN(115200); delay(200); addLog("Boot");
  loadSettings();
  addLog("addr="+settings.bleAddress+" type="+settings.bleAddrType);
  addLog("svc="+settings.serviceUuid+" wr="+settings.writeUuid);

  WiFi.disconnect(true,true); delay(200);
  beginWiFi(false);

  NimBLEDevice::init("");
  NimBLEDevice::setPower(9);
  NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_RANDOM);
  addLog("Own addr: "+String(NimBLEDevice::getAddress().toString().c_str()));

  // FIX: WLCKKP1 does NOT bond or encrypt - observed as "NOT BONDED" in nRF Connect.
  // Setting BOND flag causes the stack to wait for a pairing response that never comes.
  // Use security flags = 0 (no requirements) so connect() completes immediately.
  NimBLEDevice::setSecurityAuth(0);
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_NO_INPUT_OUTPUT);

  esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
  addLog("NimBLE init done, security: none (no-bond, no-encrypt)");
  setupWeb();

  unsigned long t0=millis();
  while(WiFi.status()!=WL_CONNECTED&&millis()-t0<12000){delay(100);server.handleClient();}
  if(WiFi.status()!=WL_CONNECTED){addLog("WiFi timeout, portal");startPortal();}
  else ensureMDNSOTA();
}

void loop(){
  server.handleClient();
  if(portalMode) dns.processNextRequest();
  if(otaReady&&WiFi.status()==WL_CONNECTED) ArduinoOTA.handle();
  serviceWiFi(); serviceMQTT(); serviceBleAutoConnect();
  if(millis()-lastStateMs>10000){
    lastStateMs=millis();
    addLog("State wifi="+String(WiFi.status()==WL_CONNECTED?"up":"down")+" ble="+String(isBleReady()?"up":"down"));
  }
  delay(5);
}
