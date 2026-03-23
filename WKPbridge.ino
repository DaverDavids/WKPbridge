// WKPbridge.ino
// ESP32-C3 BLE-to-WiFi bridge + MQTT/HA forwarding + web UI + OTA
// WiFi and BLE coexist natively on ESP32-C3 (hardware time-division mux).
// Do NOT disconnect WiFi for BLE — it is not needed and breaks the use case.

#define DEBUG_SERIAL 1

#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <ESPmDNS.h>
#include <ArduinoOTA.h>
#include <Preferences.h>
#include <NimBLEDevice.h>
#include <vector>

#include <Secrets.h>
#include "html.h"

static const char *HOSTNAME = "WKPbridge";
static const char *AP_SSID  = "WKPbridge-setup";
static const byte DNS_PORT  = 53;

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
  String  bleAddrType;         // "public" or "random"
  String  bleName;
  String  serviceUuid;
  String  writeUuid;
  String  notifyUuid;
  bool    autoConnect       = false;
  bool    writeWithResponse = false;
  uint8_t scanSeconds       = 5;
  // MQTT / Home Assistant forwarding
  String  mqttHost;            // empty = disabled
  uint16_t mqttPort            = 1883;
  String  mqttUser;
  String  mqttPass;
  String  mqttTopic;           // publish RX here; subscribe for TX commands
};

Preferences prefs;
WebServer   server(80);
DNSServer   dns;
Settings    settings;

bool portalMode       = false;
bool wifiWasConnected = false;
bool otaReady         = false;
bool mdnsReady        = false;
bool scanRunning      = false;    // guard: only one scan at a time

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
    out += hc[(data[i]>>4)&0x0F];
    out += hc[data[i]&0x0F];
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
  settings.wifiSsid          = prefs.getString("wifi_ssid",   MYSSID);
  settings.wifiPsk           = prefs.getString("wifi_psk",    MYPSK);
  settings.bleAddress        = prefs.getString("ble_addr",    "");
  settings.bleAddrType       = prefs.getString("ble_atype",   "random");
  settings.bleName           = prefs.getString("ble_name",    "");
  settings.serviceUuid       = prefs.getString("svc_uuid",    "");
  settings.writeUuid         = prefs.getString("wr_uuid",     "");
  settings.notifyUuid        = prefs.getString("nt_uuid",     "");
  settings.autoConnect       = prefs.getBool  ("auto_conn",   false);
  settings.writeWithResponse = prefs.getBool  ("wr_rsp",      false);
  settings.scanSeconds       = prefs.getUChar ("scan_sec",    5);
  settings.mqttHost          = prefs.getString("mqtt_host",   "");
  settings.mqttPort          = prefs.getUShort("mqtt_port",   1883);
  settings.mqttUser          = prefs.getString("mqtt_user",   "");
  settings.mqttPass          = prefs.getString("mqtt_pass",   "");
  settings.mqttTopic         = prefs.getString("mqtt_topic",  "wkpbridge");
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
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID);
  dns.start(DNS_PORT,"*",WiFi.softAPIP());
  portalMode=true;
  addLog("Captive portal: "+String(AP_SSID)+" "+WiFi.softAPIP().toString());
}

void stopPortal() {
  if(!portalMode) return;
  dns.stop(); WiFi.softAPdisconnect(true);
  portalMode=false; addLog("Portal stopped");
}

void beginWiFi(bool keepAp) {
  WiFi.persistent(false);
  WiFi.setAutoReconnect(true);
  WiFi.mode(keepAp ? WIFI_AP_STA : WIFI_STA);
  WiFi.setHostname(HOSTNAME);
  if(settings.wifiSsid.isEmpty()) settings.wifiSsid=MYSSID;
  if(settings.wifiPsk.isEmpty())  settings.wifiPsk=MYPSK;
  addLog("WiFi begin SSID="+settings.wifiSsid);
  WiFi.begin(settings.wifiSsid.c_str(),settings.wifiPsk.c_str());
  WiFi.setTxPower(WIFI_POWER_15dBm);
  lastWifiTryMs=millis();
}

void ensureMDNSOTA() {
  if(WiFi.status()!=WL_CONNECTED) return;
  if(!mdnsReady){
    if(MDNS.begin(HOSTNAME)){
      MDNS.addService("http","tcp",80); mdnsReady=true;
      addLog("mDNS ready: http://"+String(HOSTNAME)+".local/");
    } else addLog("mDNS start failed");
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
// MQTT forwarding (stub — wire up PubSubClient when ready)
// To enable: add PubSubClient library, uncomment #include, fill in below.
// The stub lets the rest of the code compile and the settings UI work now.
// --------------------------------------------------------------------------
// #include <PubSubClient.h>
// WiFiClient wifiClient;
// PubSubClient mqtt(wifiClient);

void mqttPublish(const String &payload) {
  if(settings.mqttHost.isEmpty()) return;
  // mqtt.publish((settings.mqttTopic+"/rx").c_str(), payload.c_str());
  addLog("MQTT publish (stub): "+payload);
}

// Called when MQTT message arrives on the command topic
// void mqttCallback(char *topic, byte *payload, unsigned int len) {
//   String hex = "";
//   for(unsigned int i=0;i<len;i++) hex += (char)payload[i];
//   sendRawHex(hex);  // forward to BLE
// }

void serviceMQTT() {
  if(settings.mqttHost.isEmpty()) return;
  // if(!mqtt.connected()) { ... reconnect ... }
  // mqtt.loop();
}

// --------------------------------------------------------------------------
// BLE callbacks
// --------------------------------------------------------------------------
class ClientCB : public NimBLEClientCallbacks {
  void onConnect(NimBLEClient *c) override {
    addLog("BLE onConnect: "+String(c->getPeerAddress().toString().c_str()));
  }
  void onDisconnect(NimBLEClient *c, int reason) override {
    (void)c; writeChr=nullptr; notifyChr=nullptr;
    addLog("BLE disconnected reason="+String(reason));
  }
};
ClientCB gClientCB;

void notifyCB(NimBLERemoteCharacteristic *pChr, uint8_t *data, size_t len, bool isNotify) {
  (void)pChr; (void)isNotify;
  lastRxHex = bytesToHex(data, len);
  addLog("RX: "+lastRxHex);
  mqttPublish(lastRxHex);  // forward to HA/MQTT
}

void deleteBleClient() {
  if(bleClient){
    if(bleClient->isConnected()) bleClient->disconnect();
    NimBLEDevice::deleteClient(bleClient); bleClient=nullptr;
  }
  writeChr=nullptr; notifyChr=nullptr;
}

bool isBleReady() {
  return bleClient && bleClient->isConnected() && writeChr;
}

// --------------------------------------------------------------------------
// BLE scan
// The key fix: always call scan->stop() + clearResults() before start().
// Without this, if a previous scan ended abnormally the state machine is
// stuck and start() returns immediately with 0 results.
// --------------------------------------------------------------------------
const NimBLEAdvertisedDevice* doScanFindTarget(uint8_t secs, const String &targetUpper) {
  if(scanRunning){
    addLog("Scan already running, skipping");
    return nullptr;
  }
  scanRunning = true;

  NimBLEScan *scan = NimBLEDevice::getScan();
  // Always stop + clear before starting — fixes "returns instantly" bug
  scan->stop();
  scan->clearResults();
  scan->setActiveScan(true);
  scan->setInterval(100);
  scan->setWindow(99);

  addLog("BLE scan "+String(secs)+"s...");
  bool ok = scan->start(secs, false);
  addLog("scan->start() returned "+String(ok?"true":"false"));

  const NimBLEScanResults results = scan->getResults();
  addLog("Scan done: "+String(results.getCount())+" device(s)");

  const NimBLEAdvertisedDevice *found = nullptr;
  String json = "["; bool first = true;
  currentTargetAddr = "";

  for(int i=0;i<results.getCount();i++){
    const NimBLEAdvertisedDevice *dev = results.getDevice(i);
    String addr = String(dev->getAddress().toString().c_str());
    String addrUp = addr; addrUp.toUpperCase();
    String name = dev->haveName() ? String(dev->getName().c_str()) : "";
    int rssi = dev->getRSSI();
    uint8_t at = dev->getAddress().getType();
    String ats = (at==BLE_ADDR_RANDOM)?"random":"public";
    addLog("  "+addrUp+" ["+ats+"] '"+name+"' rssi="+String(rssi));

    if(!first) json+=","; first=false;
    json+="{\"addr\":\""+jsonEscape(addr)+"\",\"addrType\":\""+ats+"\",\"name\":\""+jsonEscape(name)+"\",\"rssi\":"+String(rssi)+"}";

    if(!found && !targetUpper.isEmpty() && addrUp==targetUpper){ found=dev; addLog("  -> addr match"); }
    if(!found && settings.bleName.length() && name.length()){
      String n1=name; n1.toLowerCase();
      String n2=settings.bleName; n2.toLowerCase();
      if(n1.indexOf(n2)>=0){ found=dev; addLog("  -> name match '"+name+"'");
        currentTargetAddr=addr;
      }
    }
  }
  json+="]";
  lastScanJson=json;
  scanRunning=false;
  return found;
}

String scanJson() {
  String t=settings.bleAddress; t.trim(); t.toUpperCase();
  doScanFindTarget(settings.scanSeconds, t);
  return lastScanJson;
}

// --------------------------------------------------------------------------
// BLE connect
// --------------------------------------------------------------------------
bool connectBle() {
  deleteBleClient();

  String target=settings.bleAddress; target.trim(); target.toUpperCase();

  if(settings.serviceUuid.isEmpty()||settings.writeUuid.isEmpty()){
    addLog("Connect skipped: service/write UUID not set"); return false;
  }
  if(target.isEmpty()&&settings.bleName.isEmpty()){
    addLog("Connect skipped: no target address or name"); return false;
  }

  const NimBLEAdvertisedDevice *found = doScanFindTarget(settings.scanSeconds, target);
  if(!found){
    addLog("Target not found in scan — put device in advertising mode");
    return false;
  }

  addLog("Connecting to "+String(found->getAddress().toString().c_str()));
  bleClient = NimBLEDevice::createClient();
  bleClient->setClientCallbacks(&gClientCB, false);
  bleClient->setConnectionParams(12,12,0,200);
  bleClient->setConnectTimeout(10);

  if(!bleClient->connect(found)){
    addLog("connect() failed"); deleteBleClient(); return false;
  }
  addLog("Link up, discovering services...");

  NimBLERemoteService *svc = bleClient->getService(NimBLEUUID(settings.serviceUuid.c_str()));
  if(!svc){
    addLog("Service not found: "+settings.serviceUuid);
    std::vector<NimBLERemoteService*> svcs = bleClient->getServices(true);
    for(NimBLERemoteService *s : svcs)
      addLog("  Avail: "+String(s->getUUID().toString().c_str()));
    deleteBleClient(); return false;
  }
  addLog("Service found");

  writeChr = svc->getCharacteristic(NimBLEUUID(settings.writeUuid.c_str()));
  if(!writeChr){
    addLog("Write chr not found: "+settings.writeUuid);
    deleteBleClient(); return false;
  }
  addLog("Write chr ok, canWrite="+String((writeChr->canWrite()||writeChr->canWriteNoResponse())?"yes":"no"));

  if(settings.notifyUuid.length()){
    notifyChr = svc->getCharacteristic(NimBLEUUID(settings.notifyUuid.c_str()));
    if(notifyChr&&(notifyChr->canNotify()||notifyChr->canIndicate())){
      if(notifyChr->subscribe(true,notifyCB)) addLog("Notify subscribed");
      else addLog("Notify subscribe failed");
    } else addLog("Notify chr not subscribable");
  }

  addLog("BLE ready — WiFi still active for web UI / MQTT");
  return true;
}

void disconnectBle() {
  deleteBleClient();
  addLog("BLE disconnected");
}

// --------------------------------------------------------------------------
// Send packets
// --------------------------------------------------------------------------
bool sendPacket(const uint8_t *data, size_t len, const char *tag) {
  if(!isBleReady()){ addLog(String("TX failed (not ready): ")+tag); return false; }
  lastTxHex=bytesToHex(data,len);
  addLog(String("TX ")+tag+": "+lastTxHex);
  bool ok=writeChr->writeValue(data,len,settings.writeWithResponse);
  addLog(String("TX ")+tag+": "+(ok?"OK":"FAIL"));
  return ok;
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
  String ip   = WiFi.status()==WL_CONNECTED ? WiFi.localIP().toString() : "";
  String apIp = portalMode ? WiFi.softAPIP().toString() : "";
  String peer = (bleClient&&bleClient->isConnected()) ? String(bleClient->getPeerAddress().toString().c_str()) : "";
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
  json+="\"notifyUuid\":\""+jsonEscape(settings.notifyUuid)+"\",";
  json+="\"autoConnect\":"+String(settings.autoConnect?"true":"false")+",";
  json+="\"writeWithResponse\":"+String(settings.writeWithResponse?"true":"false")+",";
  json+="\"scanSeconds\":"+String(settings.scanSeconds)+",";
  json+="\"mqttHost\":\""+jsonEscape(settings.mqttHost)+"\",";
  json+="\"mqttPort\":"+String(settings.mqttPort)+",";
  json+="\"mqttUser\":\""+jsonEscape(settings.mqttUser)+"\",";
  json+="\"mqttTopic\":\""+jsonEscape(settings.mqttTopic)+"\",";
  json+="\"lastTx\":\""+jsonEscape(lastTxHex)+"\",";
  json+="\"lastRx\":\""+jsonEscape(lastRxHex)+"\",";
  json+="\"logs\":\""+jsonEscape(logBuffer)+"\",";
  json+="\"scan\":"+lastScanJson;
  json+="}";
  return json;
}

// --------------------------------------------------------------------------
// Web handlers
// --------------------------------------------------------------------------
void sendOk(const String &m)  { server.send(200,"application/json","{\"ok\":true,\"msg\":\""+jsonEscape(m)+"\"}"); }
void sendErr(const String &m) { server.send(200,"application/json","{\"ok\":false,\"msg\":\""+jsonEscape(m)+"\"}"); }

bool argBool(const char *n, bool d){
  if(!server.hasArg(n)) return d;
  String v=server.arg(n); v.toLowerCase();
  return v=="1"||v=="true"||v=="on"||v=="yes";
}

void handleRoot()  { server.send_P(200,"text/html",INDEX_HTML); }
void handleState() { server.send(200,"application/json",makeStateJson()); }
void handleScan()  { server.send(200,"application/json",scanJson()); }

void handleSaveConfig(){
  settings.bleAddress  = server.arg("bleAddress");  settings.bleAddress.trim();
  settings.bleAddrType = server.arg("bleAddrType");
  if(settings.bleAddrType!="random") settings.bleAddrType="public";
  settings.bleName     = server.arg("bleName");
  settings.serviceUuid = server.arg("serviceUuid"); settings.serviceUuid.trim();
  settings.writeUuid   = server.arg("writeUuid");   settings.writeUuid.trim();
  settings.notifyUuid  = server.arg("notifyUuid");  settings.notifyUuid.trim();
  settings.autoConnect       = argBool("autoConnect",       settings.autoConnect);
  settings.writeWithResponse = argBool("writeWithResponse", settings.writeWithResponse);
  if(server.hasArg("scanSeconds")){
    int v=server.arg("scanSeconds").toInt();
    if(v<1)v=1; if(v>20)v=20; settings.scanSeconds=(uint8_t)v;
  }
  // MQTT settings
  if(server.hasArg("mqttHost"))  settings.mqttHost  = server.arg("mqttHost");
  if(server.hasArg("mqttPort"))  settings.mqttPort  = (uint16_t)server.arg("mqttPort").toInt();
  if(server.hasArg("mqttUser"))  settings.mqttUser  = server.arg("mqttUser");
  if(server.hasArg("mqttPass"))  settings.mqttPass  = server.arg("mqttPass");
  if(server.hasArg("mqttTopic")) settings.mqttTopic = server.arg("mqttTopic");
  saveSettings();
  addLog("Config saved: addr="+settings.bleAddress+" svc="+settings.serviceUuid);
  sendOk("Config saved");
}

void handleSaveWifi(){
  settings.wifiSsid=server.arg("ssid");
  settings.wifiPsk=server.arg("psk");
  saveSettings(); beginWiFi(portalMode);
  sendOk("WiFi saved, reconnecting");
}

void handleConnect()   { connectBle()   ? sendOk("BLE connected")    : sendErr("BLE connect failed — check log"); }
void handleDisconnect(){ disconnectBle(); sendOk("BLE disconnected"); }
void handleSendFF()    { sendPacket(PKT_FF,sizeof(PKT_FF),"FF") ? sendOk("FF sent")  : sendErr("FF failed"); }
void handleSendFE()    { sendPacket(PKT_FE,sizeof(PKT_FE),"FE") ? sendOk("FE sent")  : sendErr("FE failed"); }
void handleSendRaw()   { sendRawHex(server.arg("hex"))           ? sendOk("Raw sent") : sendErr("Raw failed"); }
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
  if(up&&!wifiWasConnected){ wifiWasConnected=true; addLog("WiFi up: "+WiFi.localIP().toString()); ensureMDNSOTA(); stopPortal(); }
  if(!up&&wifiWasConnected){ wifiWasConnected=false; addLog("WiFi down"); lastWifiTryMs=millis(); }
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
  lastBleTryMs=millis();
  addLog("BLE auto-connect attempt");
  connectBle();
}

// --------------------------------------------------------------------------
// Setup / loop
// --------------------------------------------------------------------------
void setup(){
  DBG_BEGIN(115200);
  delay(200); addLog("Boot");
  loadSettings();
  addLog("addr="+settings.bleAddress+" type="+settings.bleAddrType);
  addLog("svc="+settings.serviceUuid+" wr="+settings.writeUuid);

  WiFi.disconnect(true,true); delay(200);
  beginWiFi(false);

  // Init BLE AFTER WiFi.begin() — coexistence scheduler starts with WiFi
  NimBLEDevice::init("");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);
  addLog("NimBLE init done");

  setupWeb();

  unsigned long t0=millis();
  while(WiFi.status()!=WL_CONNECTED&&millis()-t0<12000){delay(100);server.handleClient();}
  if(WiFi.status()!=WL_CONNECTED){addLog("WiFi timeout, starting portal");startPortal();}
  else ensureMDNSOTA();
}

void loop(){
  server.handleClient();
  if(portalMode) dns.processNextRequest();
  if(otaReady&&WiFi.status()==WL_CONNECTED) ArduinoOTA.handle();
  serviceWiFi();
  serviceMQTT();
  serviceBleAutoConnect();
  if(millis()-lastStateMs>10000){
    lastStateMs=millis();
    addLog("State wifi="+String(WiFi.status()==WL_CONNECTED?"up":"down")
          +" ble="+String(isBleReady()?"up":"down"));
  }
  delay(5);
}
