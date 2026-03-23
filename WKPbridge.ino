// WKPbridge.ino
// ESP32-C3 BLE bridge + web UI + OTA + captive portal fallback

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
  #define DBG_PRINT(...)  Serial.printf(__VA_ARGS__)
  #define DBG_PRINTLN(x)  Serial.println(x)
#else
  #define DBG_BEGIN(x)
  #define DBG_PRINT(...)
  #define DBG_PRINTLN(x)
#endif

// --------------------------------------------------------------------------
// Settings
// --------------------------------------------------------------------------
struct Settings {
  String  wifiSsid;
  String  wifiPsk;
  String  bleAddress;          // target MAC
  String  bleAddrType;         // "public" or "random"
  String  bleName;             // substring match fallback for scan
  String  serviceUuid;
  String  writeUuid;
  String  notifyUuid;
  bool    autoConnect       = false;
  bool    writeWithResponse = true;
  uint8_t scanSeconds       = 4;
};

Preferences prefs;
WebServer   server(80);
DNSServer   dns;
Settings    settings;

bool portalMode      = false;
bool wifiWasConnected = false;
bool otaReady        = false;
bool mdnsReady       = false;

unsigned long lastWifiTryMs = 0;
unsigned long lastBleTryMs  = 0;
unsigned long lastStateMs   = 0;

String logBuffer;
String lastScanJson  = "[]";
String lastTxHex;
String lastRxHex;
String currentTargetAddr;

NimBLEClient              *bleClient = nullptr;
NimBLERemoteCharacteristic *writeChr  = nullptr;
NimBLERemoteCharacteristic *notifyChr = nullptr;

static const uint8_t PKT_FF[8] = {0xDE,0xC0,0xAD,0xDE,0xFF,0x01,0x1E,0xF1};
static const uint8_t PKT_FE[8] = {0xDE,0xC0,0xAD,0xDE,0xFE,0x01,0x1E,0xF1};

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------
String jsonEscape(const String &in) {
  String out;
  out.reserve(in.length() + 16);
  for (size_t i = 0; i < in.length(); i++) {
    char c = in[i];
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '"':  out += "\\\""; break;
      case '\n': out += "\\n"; break;
      case '\r': break;
      case '\t': out += "\\t"; break;
      default:
        if ((uint8_t)c < 32) out += ' ';
        else out += c;
        break;
    }
  }
  return out;
}

void addLog(const String &line) {
  String s = String(millis()) + " | " + line;
  logBuffer += s + "\n";
  if (logBuffer.length() > 14000)
    logBuffer.remove(0, logBuffer.length() - 14000);
  DBG_PRINTLN(s);
}

String bytesToHex(const uint8_t *data, size_t len) {
  const char *hc = "0123456789ABCDEF";
  String out;
  out.reserve(len * 3);
  for (size_t i = 0; i < len; i++) {
    out += hc[(data[i] >> 4) & 0x0F];
    out += hc[data[i] & 0x0F];
    if (i + 1 < len) out += ' ';
  }
  return out;
}

bool parseHexString(String s, std::vector<uint8_t> &out) {
  out.clear();
  s.replace("0x",""); s.replace("0X","");
  s.replace(","," "); s.replace(":"," "); s.replace("-"," ");
  while (s.indexOf("  ") >= 0) s.replace("  "," ");
  s.trim();
  if (s.isEmpty()) return false;
  int start = 0;
  while (start < (int)s.length()) {
    while (start < (int)s.length() && s[start] == ' ') start++;
    if (start >= (int)s.length()) break;
    int end = s.indexOf(' ', start);
    if (end < 0) end = s.length();
    String tok = s.substring(start, end); tok.trim();
    if (tok.isEmpty()) { start = end+1; continue; }
    if (tok.length() > 2) return false;
    char *ep = nullptr;
    long v = strtol(tok.c_str(), &ep, 16);
    if (!ep || *ep != 0 || v < 0 || v > 255) return false;
    out.push_back((uint8_t)v);
    start = end + 1;
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
  settings.bleAddrType       = prefs.getString("ble_atype",  "public");
  settings.bleName           = prefs.getString("ble_name",   "");
  settings.serviceUuid       = prefs.getString("svc_uuid",   "");
  settings.writeUuid         = prefs.getString("wr_uuid",    "");
  settings.notifyUuid        = prefs.getString("nt_uuid",    "");
  settings.autoConnect       = prefs.getBool  ("auto_conn",  false);
  settings.writeWithResponse = prefs.getBool  ("wr_rsp",     true);
  settings.scanSeconds       = prefs.getUChar ("scan_sec",   4);
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
  prefs.end();
  addLog("Settings saved to flash");
}

// --------------------------------------------------------------------------
// WiFi
// --------------------------------------------------------------------------
void startPortal() {
  if (portalMode) return;
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID);
  dns.start(DNS_PORT, "*", WiFi.softAPIP());
  portalMode = true;
  addLog("Captive portal started: SSID=" + String(AP_SSID) + " IP=" + WiFi.softAPIP().toString());
}

void stopPortal() {
  if (!portalMode) return;
  dns.stop();
  WiFi.softAPdisconnect(true);
  portalMode = false;
  addLog("Captive portal stopped");
}

void beginWiFi(bool keepAp) {
  WiFi.persistent(false);
  WiFi.setAutoReconnect(true);
  WiFi.mode(keepAp ? WIFI_AP_STA : WIFI_STA);
  WiFi.setHostname(HOSTNAME);
  if (settings.wifiSsid.isEmpty()) settings.wifiSsid = MYSSID;
  if (settings.wifiPsk.isEmpty())  settings.wifiPsk  = MYPSK;
  addLog("WiFi begin SSID=" + settings.wifiSsid);
  WiFi.begin(settings.wifiSsid.c_str(), settings.wifiPsk.c_str());
  WiFi.setTxPower(WIFI_POWER_15dBm);
  lastWifiTryMs = millis();
}

void ensureMDNSOTA() {
  if (WiFi.status() != WL_CONNECTED) return;
  if (!mdnsReady) {
    if (MDNS.begin(HOSTNAME)) {
      MDNS.addService("http","tcp",80);
      mdnsReady = true;
      addLog("mDNS ready: http://" + String(HOSTNAME) + ".local/");
    } else {
      addLog("mDNS start failed");
    }
  }
  if (!otaReady) {
    ArduinoOTA.setHostname(HOSTNAME);
    ArduinoOTA.onStart([]() { addLog("OTA start"); });
    ArduinoOTA.onEnd([]()   { addLog("OTA end");   });
    ArduinoOTA.onError([](ota_error_t e) { addLog("OTA error " + String((int)e)); });
    ArduinoOTA.begin();
    otaReady = true;
    addLog("OTA ready");
  }
}

// --------------------------------------------------------------------------
// BLE callbacks
// --------------------------------------------------------------------------
class ClientCB : public NimBLEClientCallbacks {
  void onConnect(NimBLEClient *c) override {
    addLog("BLE connected: " + String(c->getPeerAddress().toString().c_str()));
  }
  void onDisconnect(NimBLEClient *c, int reason) override {
    (void)c;
    writeChr  = nullptr;
    notifyChr = nullptr;
    addLog("BLE disconnected, reason=" + String(reason));
  }
};
ClientCB gClientCB;

void notifyCB(NimBLERemoteCharacteristic *pChr, uint8_t *data, size_t len, bool isNotify) {
  (void)pChr; (void)isNotify;
  lastRxHex = bytesToHex(data, len);
  addLog("RX: " + lastRxHex);
}

// --------------------------------------------------------------------------
// BLE scan
// --------------------------------------------------------------------------
void deleteBleClient() {
  if (bleClient) {
    if (bleClient->isConnected()) bleClient->disconnect();
    NimBLEDevice::deleteClient(bleClient);
    bleClient = nullptr;
  }
  writeChr  = nullptr;
  notifyChr = nullptr;
}

bool isBleReady() {
  return bleClient && bleClient->isConnected() && writeChr;
}

// Returns JSON array of discovered devices including addrType
String scanJson() {
  NimBLEScan *scan = NimBLEDevice::getScan();
  scan->setActiveScan(true);
  scan->setInterval(45);
  scan->setWindow(15);

  addLog("BLE scan start " + String(settings.scanSeconds) + "s");
  scan->start(settings.scanSeconds, false);
  const auto &results = scan->getResults();

  String json = "[";
  bool first = true;
  currentTargetAddr = "";

  for (int i = 0; i < results.getCount(); i++) {
    const NimBLEAdvertisedDevice *dev = results.getDevice(i);
    String addr  = String(dev->getAddress().toString().c_str());
    String name  = dev->haveName() ? String(dev->getName().c_str()) : "";
    int    rssi  = dev->getRSSI();
    // NimBLE 2.x: getAddress().getType() returns uint8_t
    uint8_t atype = dev->getAddress().getType();
    String  atypeStr = (atype == BLE_ADDR_RANDOM) ? "random" : "public";

    if (!first) json += ",";
    first = false;
    json += "{";
    json += "\"addr\":\""    + jsonEscape(addr)     + "\",";
    json += "\"addrType\":\"" + atypeStr             + "\",";
    json += "\"name\":\""    + jsonEscape(name)     + "\",";
    json += "\"rssi\":"      + String(rssi);
    json += "}";

    if (currentTargetAddr.isEmpty() && settings.bleName.length() && name.length()) {
      String n1 = name;             n1.toLowerCase();
      String n2 = settings.bleName; n2.toLowerCase();
      if (n1.indexOf(n2) >= 0) currentTargetAddr = addr;
    }
  }
  json += "]";
  scan->clearResults();
  lastScanJson = json;
  addLog("BLE scan done, count=" + String(results.getCount()));
  return json;
}

// --------------------------------------------------------------------------
// BLE connect
// --------------------------------------------------------------------------
NimBLEClient* makeClient() {
  NimBLEClient *c = NimBLEDevice::createClient();
  c->setClientCallbacks(&gClientCB, false);
  c->setConnectionParams(12, 12, 0, 200);
  c->setConnectTimeout(5);
  return c;
}

// Try explicit type first, then fall back to the other one
bool connectByAddressString(const String &target, const String &addrTypeStr) {
  std::string s(target.c_str());

  uint8_t primaryType   = (addrTypeStr == "random") ? BLE_ADDR_RANDOM : BLE_ADDR_PUBLIC;
  uint8_t secondaryType = (primaryType == BLE_ADDR_PUBLIC) ? BLE_ADDR_RANDOM : BLE_ADDR_PUBLIC;

  bleClient = makeClient();
  if (bleClient->connect(NimBLEAddress(s, primaryType))) {
    addLog("BLE connected addr_type=" + addrTypeStr);
    return true;
  }
  deleteBleClient();

  addLog("BLE connect failed with " + addrTypeStr + ", trying other type");
  bleClient = makeClient();
  if (bleClient->connect(NimBLEAddress(s, secondaryType))) {
    addLog("BLE connected with fallback addr_type");
    return true;
  }
  deleteBleClient();
  return false;
}

bool connectBle() {
  deleteBleClient();

  String target = settings.bleAddress;
  target.trim();

  if (target.isEmpty() && settings.bleName.length()) {
    scanJson();
    target = currentTargetAddr;
    if (!target.isEmpty()) addLog("Resolved target from name: " + target);
  }
  if (target.isEmpty()) {
    addLog("BLE connect skipped: no target address");
    return false;
  }
  if (settings.serviceUuid.isEmpty() || settings.writeUuid.isEmpty()) {
    addLog("BLE connect skipped: service/write UUID not configured");
    return false;
  }

  addLog("BLE connect to " + target + " type=" + settings.bleAddrType);
  if (!connectByAddressString(target, settings.bleAddrType)) {
    addLog("BLE connect failed");
    return false;
  }

  NimBLERemoteService *svc = bleClient->getService(NimBLEUUID(settings.serviceUuid.c_str()));
  if (!svc) {
    addLog("BLE service not found: " + settings.serviceUuid);
    deleteBleClient();
    return false;
  }

  writeChr = svc->getCharacteristic(NimBLEUUID(settings.writeUuid.c_str()));
  if (!writeChr) {
    addLog("BLE write chr not found: " + settings.writeUuid);
    deleteBleClient();
    return false;
  }

  if (settings.notifyUuid.length()) {
    notifyChr = svc->getCharacteristic(NimBLEUUID(settings.notifyUuid.c_str()));
    if (notifyChr && (notifyChr->canNotify() || notifyChr->canIndicate())) {
      if (notifyChr->subscribe(true, notifyCB))
        addLog("Subscribed to notifications");
      else
        addLog("Notify subscribe failed");
    } else {
      addLog("Notify chr missing or not subscribable");
    }
  }
  addLog("BLE ready");
  return true;
}

void disconnectBle() {
  deleteBleClient();
  addLog("BLE manually disconnected");
}

// --------------------------------------------------------------------------
// Send packets
// --------------------------------------------------------------------------
bool sendPacket(const uint8_t *data, size_t len, const char *tag) {
  if (!isBleReady()) {
    addLog(String("TX failed, BLE not ready: ") + tag);
    return false;
  }
  lastTxHex = bytesToHex(data, len);
  addLog(String("TX ") + tag + ": " + lastTxHex);
  bool ok = writeChr->writeValue(data, len, settings.writeWithResponse);
  addLog(String("TX result ") + tag + ": " + (ok ? "OK" : "FAIL"));
  return ok;
}

bool sendRawHex(const String &hex) {
  std::vector<uint8_t> buf;
  if (!parseHexString(hex, buf)) {
    addLog("Raw hex parse failed");
    return false;
  }
  return sendPacket(buf.data(), buf.size(), "RAW");
}

// --------------------------------------------------------------------------
// State JSON (for web UI polling)
// --------------------------------------------------------------------------
String makeStateJson() {
  String json;
  json.reserve(4096);
  String ip     = WiFi.status()==WL_CONNECTED ? WiFi.localIP().toString() : "";
  String apIp   = portalMode ? WiFi.softAPIP().toString() : "";
  String blePeer = (bleClient && bleClient->isConnected())
                 ? String(bleClient->getPeerAddress().toString().c_str()) : "";

  json += "{";
  json += "\"hostname\":\""        + String(HOSTNAME)                                     + "\",";
  json += "\"wifiConnected\":"      + String(WiFi.status()==WL_CONNECTED?"true":"false")   + ",";
  json += "\"portalMode\":"         + String(portalMode?"true":"false")                   + ",";
  json += "\"ip\":\""               + jsonEscape(ip)                                       + "\",";
  json += "\"apIp\":\""             + jsonEscape(apIp)                                     + "\",";
  json += "\"ssid\":\""             + jsonEscape(settings.wifiSsid)                        + "\",";
  json += "\"mac\":\""              + jsonEscape(WiFi.macAddress())                        + "\",";
  json += "\"rssi\":"               + String(WiFi.status()==WL_CONNECTED?WiFi.RSSI():0)   + ",";
  json += "\"bleConnected\":"       + String(isBleReady()?"true":"false")                  + ",";
  json += "\"blePeer\":\""          + jsonEscape(blePeer)                                  + "\",";
  json += "\"bleAddress\":\""       + jsonEscape(settings.bleAddress)                      + "\",";
  json += "\"bleAddrType\":\""      + jsonEscape(settings.bleAddrType)                     + "\",";
  json += "\"bleName\":\""          + jsonEscape(settings.bleName)                         + "\",";
  json += "\"serviceUuid\":\""      + jsonEscape(settings.serviceUuid)                     + "\",";
  json += "\"writeUuid\":\""        + jsonEscape(settings.writeUuid)                       + "\",";
  json += "\"notifyUuid\":\""       + jsonEscape(settings.notifyUuid)                      + "\",";
  json += "\"autoConnect\":"        + String(settings.autoConnect?"true":"false")          + ",";
  json += "\"writeWithResponse\":"  + String(settings.writeWithResponse?"true":"false")   + ",";
  json += "\"scanSeconds\":"        + String(settings.scanSeconds)                         + ",";
  json += "\"lastTx\":\""           + jsonEscape(lastTxHex)                                + "\",";
  json += "\"lastRx\":\""           + jsonEscape(lastRxHex)                                + "\",";
  json += "\"logs\":\""             + jsonEscape(logBuffer)                                + "\",";
  json += "\"scan\":"               + lastScanJson;
  json += "}";
  return json;
}

// --------------------------------------------------------------------------
// Web server handlers
// --------------------------------------------------------------------------
void sendOk(const String &msg)  { server.send(200,"application/json","{\"ok\":true,\"msg\":\"" +jsonEscape(msg)+"\"}"); }
void sendErr(const String &msg) { server.send(200,"application/json","{\"ok\":false,\"msg\":\"" +jsonEscape(msg)+"\"}"); }

bool argBool(const char *name, bool defVal) {
  if (!server.hasArg(name)) return defVal;
  String v = server.arg(name); v.toLowerCase();
  return v=="1"||v=="true"||v=="on"||v=="yes";
}

void handleRoot()      { server.send_P(200, "text/html", INDEX_HTML); }
void handleState()     { server.send(200, "application/json", makeStateJson()); }
void handleScan()      { server.send(200, "application/json", scanJson()); }

void handleSaveConfig() {
  settings.bleAddress        = server.arg("bleAddress");
  settings.bleAddrType       = server.arg("bleAddrType");
  if (settings.bleAddrType != "random") settings.bleAddrType = "public";
  settings.bleName           = server.arg("bleName");
  settings.serviceUuid       = server.arg("serviceUuid");
  settings.writeUuid         = server.arg("writeUuid");
  settings.notifyUuid        = server.arg("notifyUuid");
  settings.autoConnect       = argBool("autoConnect",       settings.autoConnect);
  settings.writeWithResponse = argBool("writeWithResponse", settings.writeWithResponse);
  if (server.hasArg("scanSeconds")) {
    int v = server.arg("scanSeconds").toInt();
    if (v < 1) v = 1;
    if (v > 20) v = 20;
    settings.scanSeconds = (uint8_t)v;
  }
  saveSettings();
  sendOk("Config saved");
}

void handleSaveWifi() {
  settings.wifiSsid = server.arg("ssid");
  settings.wifiPsk  = server.arg("psk");
  saveSettings();
  beginWiFi(portalMode);
  sendOk("WiFi saved, reconnect started");
}

void handleConnect()    { connectBle()    ? sendOk("BLE connected")    : sendErr("BLE connect failed"); }
void handleDisconnect() { disconnectBle(); sendOk("BLE disconnected"); }
void handleSendFF()     { sendPacket(PKT_FF,sizeof(PKT_FF),"FF") ? sendOk("FF sent")  : sendErr("FF send failed"); }
void handleSendFE()     { sendPacket(PKT_FE,sizeof(PKT_FE),"FE") ? sendOk("FE sent")  : sendErr("FE send failed"); }
void handleSendRaw()    { sendRawHex(server.arg("hex"))           ? sendOk("Raw sent") : sendErr("Raw send failed"); }

void handleClearLog() {
  logBuffer = ""; lastTxHex = ""; lastRxHex = "";
  sendOk("Log cleared");
}

void handleReboot() {
  sendOk("Rebooting"); delay(200); ESP.restart();
}

void setupWeb() {
  server.on("/",                HTTP_GET,  handleRoot);
  server.on("/api/state",       HTTP_GET,  handleState);
  server.on("/api/scan",        HTTP_GET,  handleScan);
  server.on("/api/saveConfig",  HTTP_POST, handleSaveConfig);
  server.on("/api/saveWifi",    HTTP_POST, handleSaveWifi);
  server.on("/api/connect",     HTTP_POST, handleConnect);
  server.on("/api/disconnect",  HTTP_POST, handleDisconnect);
  server.on("/api/sendFF",      HTTP_POST, handleSendFF);
  server.on("/api/sendFE",      HTTP_POST, handleSendFE);
  server.on("/api/sendRaw",     HTTP_POST, handleSendRaw);
  server.on("/api/clearLog",    HTTP_POST, handleClearLog);
  server.on("/api/reboot",      HTTP_POST, handleReboot);
  server.onNotFound([]() {
    if (portalMode) { server.sendHeader("Location","/",true); server.send(302,"text/plain",""); }
    else server.send(404,"text/plain","Not found");
  });
  server.begin();
  addLog("HTTP server started");
}

// --------------------------------------------------------------------------
// Service loops
// --------------------------------------------------------------------------
void serviceWiFi() {
  bool connected = (WiFi.status() == WL_CONNECTED);
  if (connected && !wifiWasConnected) {
    wifiWasConnected = true;
    addLog("WiFi connected: " + WiFi.localIP().toString());
    ensureMDNSOTA();
    stopPortal();
  }
  if (!connected && wifiWasConnected) {
    wifiWasConnected = false;
    addLog("WiFi disconnected");
    lastWifiTryMs = millis();
  }
  if (!connected) {
    if (millis() - lastWifiTryMs > 15000) beginWiFi(portalMode);
    if (!portalMode && millis() > 30000 && millis() - lastWifiTryMs > 10000) startPortal();
  }
}

void serviceBleAutoConnect() {
  if (!settings.autoConnect) return;
  if (isBleReady()) return;
  if (settings.serviceUuid.isEmpty() || settings.writeUuid.isEmpty()) return;
  if (millis() - lastBleTryMs < 10000) return;
  lastBleTryMs = millis();
  addLog("BLE auto-connect attempt");
  connectBle();
}

// --------------------------------------------------------------------------
// Setup / loop
// --------------------------------------------------------------------------
void setup() {
  DBG_BEGIN(115200);
  delay(200);
  addLog("Boot");
  loadSettings();

  WiFi.disconnect(true, true);
  delay(200);
  beginWiFi(false);

  NimBLEDevice::init("");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);

  setupWeb();

  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 12000) {
    delay(100);
    server.handleClient();
  }

  if (WiFi.status() != WL_CONNECTED) {
    addLog("WiFi timeout, starting captive portal");
    startPortal();
  } else {
    ensureMDNSOTA();
  }
}

void loop() {
  server.handleClient();
  if (portalMode) dns.processNextRequest();
  if (otaReady && WiFi.status() == WL_CONNECTED) ArduinoOTA.handle();
  serviceWiFi();
  serviceBleAutoConnect();
  if (millis() - lastStateMs > 10000) {
    lastStateMs = millis();
    addLog("State wifi=" + String(WiFi.status()==WL_CONNECTED?"up":"down")
         + " ble=" + String(isBleReady()?"up":"down"));
  }
  delay(5);
}
