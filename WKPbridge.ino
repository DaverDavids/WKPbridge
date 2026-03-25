// WKPbridge.ino
// ESP32-C3 BLE-to-WiFi bridge for Wyze Wireless Keypad (WLCKKP1)
//
// Fix log:
//  r1-r5: scan/connect fixes, debug
//  r6: Dump full manufacturer data bytes; on connect failure log HCI status.
//  r7: Correct Wyze service/char UUIDs (0xFE50/FE51/FE52).
//      Added all known Wyze ad names (KP-01, DingDing, Wyze Lock, DD-Fact).
//      Named packet presets: Bind, Unlock, Test-Keypress.
//      Full GATT dump on connect: all services + characteristics + properties.
//      Richer mfr data decode (device type, pairing/lock status, MAC).
//      Added /api/sendBind, /api/sendUnlock, /api/sendKP endpoints.
//      Connection params logged. Log buffer expanded to 24KB.
//  r7a: Fix NimBLE 2.x API: getConnId() removed; getCharacteristics() returns
//       reference not pointer. Connection params now logged in onAuthenticationComplete.
//  r7b: Fix NimBLEConnInfo: getSupervisionTimeout() -> getConnTimeout() (NimBLE 2.x).
//  r7c: Fix setConnectTimeout() units: NimBLE 2.x takes units of 10ms, not seconds.
//       10 -> 500 (=5s). Add post-scan settle delay (500ms) + coex settle (100ms)
//       before connect. Increase inter-attempt delay 200->400ms to avoid EALREADY
//       race with stale onDisconnect. dumpAllGatt() logs when not connected.
//  r7d: Fix EALREADY false-negative: after connect() returns false, check isConnected()
//       before declaring failure -- EALREADY can occur when connection actually succeeded
//       at controller level. Calling deleteBleClient() in that case sends a disconnect
//       to the keypad (0x216 = local host terminated), causing error beep + exit pairing.
//       Added extensive debug logging throughout connect/callback path.
//  r8:  Decompile analysis conclusions:
//       - Transport is NUS (6e400001/02/03), NOT 0xFE50/FE51/FE52.
//       - Default UUIDs switched to NUS. Stored settings migrated on boot.
//       - Removed updateConnParams() call.
//       - Auto-probe on connect: send PKT_FF after subscribing notify.
//  r9:  Decompile deep-dive -- AES-ECB auth handshake:
//       - Hardcoded key at 0x00036df0: "d37fcd6903fe6e69" (ASCII hex) =
//         0xD3,0x7F,0xCD,0x69,0x03,0xFE,0x6E,0x69 zero-padded to 16 bytes.
//       - FUN_00028158: AES-ECB 16-byte block encrypt (mbedtls).
//       - notifyCB: detect 8-byte nonce -> AES-ECB encrypt -> send 8-byte auth.
//       - REMOVED PKT_FF auto-probe. Keypad initiates -- wait silently.
//  r10: MAJOR: Flip to PERIPHERAL mode.
//       ROOT CAUSE: keypad IS the BLE central. It scans for the lock (which
//       advertises NUS), then connects TO the lock. Run as BLE PERIPHERAL.
//  r10a: Fix compile: remove setAdvertisementType() (not in NimBLE 2.x).
//  r10b: Key fixes after first peripheral test:
//       PROBLEM 1: Keypad never connected despite pairing mode.
//       - MAC byte order in mfr data was WRONG. NimBLEAddress::getBase()->val
//         is stored LSB-first (little-endian). Real lock mfr data has MAC
//         MSB-first. Must reverse: mac[5]..mac[0] not mac[0]..mac[5].
//       - Added /api/tryLockMac: advertise using the REAL lock's known MAC
//         (E2:79:A5:DC:36:4D) in the mfr data. The keypad may filter by MAC.
//         Try this if our own MAC doesn't work.
//       - Coex set to BT priority during peripheral advertising (not balanced).
//         WiFi coex was likely starving BLE advertising slots.
//       - Adv interval tightened: 20ms/20ms (was 20/40ms).
//       PROBLEM 2: Pairing mode detection -- added /api/scanPairing which
//         scans specifically for keypad in pairing mode (devType=0x07, KP-01).
//         Logs pairing-mode byte if present.
//       PROBLEM 3: Settings/UI -- restored bleAddress, bleAddrType, bleName,
//         serviceUuid, writeUuid, notifyUuid fields to makeStateJson() and
//         handleSaveConfig() so UI doesn't lose them.

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

// ---- NUS UUIDs (Nordic UART Service) ----
static const char *NUS_SERVICE_UUID = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
static const char *NUS_RX_UUID      = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"; // keypad WRITES here
static const char *NUS_TX_UUID      = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"; // we NOTIFY here

static const char *WYZE_SERVICE_UUID = "0000fe50-0000-1000-8000-00805f9b34fb";
static const uint16_t WYZE_COMPANY_ID = 0x4459;

static const char * const WYZE_ADV_NAMES[] = {
  "Wyze Lock", "DingDing", "KP-01", "DD-Fact", nullptr
};

// AES-ECB key from decompile (0x00036df0: "d37fcd6903fe6e69" ASCII hex)
static const uint8_t AES_KEY[16] = {
  0xD3, 0x7F, 0xCD, 0x69, 0x03, 0xFE, 0x6E, 0x69,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Real lock MAC (seen in scan: E2:79:A5:DC:36:4D) -- used by /api/tryLockMac
// to advertise with the lock's actual MAC in mfr data, in case keypad filters by MAC.
static const uint8_t REAL_LOCK_MAC[6] = {0xE2, 0x79, 0xA5, 0xDC, 0x36, 0x4D};

// ---- Peripheral state ----
static NimBLEServer         *bleServer    = nullptr;
static NimBLEService        *nusService   = nullptr;
static NimBLECharacteristic *rxChr        = nullptr;
static NimBLECharacteristic *txChr        = nullptr;
static bool          gAdvConnected    = false;
static uint32_t      gConnHandle      = 0xFFFF;
static unsigned long gConnectedAtMs   = 0;
static String        gAdvPeer         = "";
static bool          gUseLockMac      = false; // if true, use REAL_LOCK_MAC in adv

// ---- Nonce / auth state ----
static uint8_t  gLastNonce[8]  = {0};
static bool     gNonceReceived = false;

// ---- Legacy stubs ----
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
String jsonEscape(const String &in) {
  String out; out.reserve(in.length()+16);
  for(size_t i=0;i<in.length();i++){
    char c=in[i]; switch(c){
      case '\\': out+="\\\\"; break; case '"': out+"\\\""; break;
      case '\n': out+="\\n";  break; case '\r': break;
      case '\t': out+="\\t";  break;
      default: if((uint8_t)c<32)out+=' '; else out+=c; break;
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
  settings.bleName     =prefs.getString("ble_name", "KP-01");
  settings.serviceUuid =prefs.getString("svc_uuid", NUS_SERVICE_UUID);
  settings.writeUuid   =prefs.getString("wr_uuid",  NUS_RX_UUID);
  settings.notifyUuid  =prefs.getString("nt_uuid",  NUS_TX_UUID);
  settings.autoConnect      =prefs.getBool  ("auto_conn",false);
  settings.writeWithResponse=prefs.getBool  ("wr_rsp",   false);
  settings.scanSeconds      =prefs.getUChar ("scan_sec", 5);
  settings.mqttHost =prefs.getString("mqtt_host",""); settings.mqttPort=prefs.getUShort("mqtt_port",1883);
  settings.mqttUser =prefs.getString("mqtt_user",""); settings.mqttPass=prefs.getString("mqtt_pass","");
  settings.mqttTopic=prefs.getString("mqtt_topic","wkpbridge");
  prefs.end();
  if(settings.serviceUuid == WYZE_SERVICE_UUID) {
    settings.serviceUuid = NUS_SERVICE_UUID;
    settings.writeUuid   = NUS_RX_UUID;
    settings.notifyUuid  = NUS_TX_UUID;
    addLog("r10 migrate: UUIDs reset to NUS");
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
// AES-ECB
// --------------------------------------------------------------------------
bool computeAuthResponse(const uint8_t *nonce8, uint8_t *resp8) {
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
// Peripheral TX
// --------------------------------------------------------------------------
bool sendNotify(const uint8_t *d, size_t l, const char *tag) {
  if(!gAdvConnected||!txChr){addLog(String("TX NOTIFY failed: not connected - ")+tag);return false;}
  lastTxHex=bytesToHex(d,l);
  addLog(String("TX NOTIFY ")+tag+": "+lastTxHex);
  bool ok=txChr->notify(d,l);
  addLog(String("TX NOTIFY result: ")+(ok?"OK":"FAIL"));
  return ok;
}

// --------------------------------------------------------------------------
// Decode RX packet from keypad
// --------------------------------------------------------------------------
void decodeRxPacket(const uint8_t *d, size_t l) {
  addLog("  RAW["+String(l)+"]: "+bytesToHex(d,l));

  // dd_protocol magic header DE C0 AD DE
  if(l>=5 && d[0]==0xDE && d[1]==0xC0 && d[2]==0xAD && d[3]==0xDE) {
    uint8_t op=d[4];
    String opName;
    switch(op){
      case 0x00: opName="UNLOCK_CMD"; break;
      case 0x01: opName="BIND_CMD"; break;
      case 0x02: opName="KEYPRESS_CMD"; break;
      case 0xFE: opName="PROBE_FE"; break;
      case 0xFF: opName="GET_RANDOM"; break;
      default:   opName="OP_0x"+String(op,HEX); break;
    }
    String payload=(l>5)?bytesToHex(d+5,l-5):"(none)";
    addLog("  -> dd_proto op="+opName+" payload["+String(l-5)+"]="+payload);
    if(op==0xFF && l>=13)
      addLog("  -> GET_RANDOM payload (possible nonce): "+bytesToHex(d+5,l-5));
    mqttPublish(bytesToHex(d,l));
    return;
  }

  // 8-byte unframed nonce (GET_RANDOM challenge)
  if(l==8) {
    addLog("  -> 8-byte unframed = GET_RANDOM nonce challenge");
    memcpy(gLastNonce,d,8); gNonceReceived=true;
    uint8_t resp[8]={0};
    if(computeAuthResponse(gLastNonce,resp)){
      addLog("  -> AES-ECB resp: "+bytesToHex(resp,8));
      delay(20);
      bool ok=sendNotify(resp,8,"AUTH_RESP");
      addLog(ok?"  -> Auth sent OK":"  -> Auth FAILED");
    } else { addLog("  -> AES FAILED"); }
    mqttPublish(bytesToHex(d,l));
    return;
  }

  addLog("  -> Unknown pkt len="+String(l)+" (not magic, not 8b) -- logging raw for analysis");
  mqttPublish(bytesToHex(d,l));
}

// --------------------------------------------------------------------------
// BLE Server callbacks
// --------------------------------------------------------------------------
class ServerCB : public NimBLEServerCallbacks {
public:
  void onConnect(NimBLEServer *srv, NimBLEConnInfo &info) override {
    gAdvConnected=true; gConnHandle=info.getConnHandle();
    gConnectedAtMs=millis(); gAdvPeer=String(info.getAddress().toString().c_str());
    addLog(">>> PERIPH onConnect peer="+gAdvPeer+" handle="+String(gConnHandle)+" t="+String(gConnectedAtMs)+"ms");
    addLog("    itvl="+String(info.getConnInterval())+" latency="+String(info.getConnLatency())
           +" timeout="+String(info.getConnTimeout())+" mtu="+String(info.getMTU()));
    NimBLEDevice::getAdvertising()->stop();
    addLog("    Adv stopped");
  }
  void onDisconnect(NimBLEServer *srv, NimBLEConnInfo &info, int reason) override {
    unsigned long dur=gConnectedAtMs?(millis()-gConnectedAtMs):0;
    addLog(">>> PERIPH onDisconnect peer="+String(info.getAddress().toString().c_str())
           +" reason=0x"+String(reason,HEX)+" (HCI=0x"+String(reason&0xFF,HEX)+")"
           +" dur="+String(dur)+"ms nonceRx="+String(gNonceReceived?"YES":"NO"));
    gAdvConnected=false; gConnHandle=0xFFFF; gConnectedAtMs=0; gAdvPeer=""; gNonceReceived=false;
    addLog("    Restarting adv...");
    NimBLEDevice::getAdvertising()->start();
    addLog("    Adv restarted");
  }
  void onAuthenticationComplete(NimBLEConnInfo &info) override {
    addLog(">>> PERIPH onAuthComplete enc="+String(info.isEncrypted())
           +" bonded="+String(info.isBonded())+" auth="+String(info.isAuthenticated()));
  }
  void onMTUChange(uint16_t mtu, NimBLEConnInfo &info) override {
    addLog(">>> PERIPH onMTUChange mtu="+String(mtu));
  }
};
ServerCB gServerCB;

class RxCharCB : public NimBLECharacteristicCallbacks {
public:
  void onWrite(NimBLECharacteristic *chr, NimBLEConnInfo &info) override {
    std::string val=chr->getValue(); size_t l=val.size();
    const uint8_t *d=(const uint8_t*)val.data();
    lastRxHex=bytesToHex(d,l);
    unsigned long t=gConnectedAtMs?(millis()-gConnectedAtMs):0;
    addLog("RX WRITE len="+String(l)+" tSinceConn="+String(t)+"ms from="+String(info.getAddress().toString().c_str()));
    decodeRxPacket(d,l);
  }
  void onSubscribe(NimBLECharacteristic *chr, NimBLEConnInfo &info, uint16_t subValue) override {
    unsigned long t=gConnectedAtMs?(millis()-gConnectedAtMs):0;
    addLog(">>> TX chr subscribe val=0x"+String(subValue,HEX)+" tSinceConn="+String(t)+"ms peer="+String(info.getAddress().toString().c_str()));
    if(subValue==1) addLog("    Keypad subscribed to notify -- waiting for nonce write to NUS_RX");
    else if(subValue==0) addLog("    Keypad UNsubscribed from notify");
  }
};
RxCharCB gRxCharCB;

// --------------------------------------------------------------------------
// Build mfr data (r10b: correct byte order -- MSB first in packet)
// NimBLEAddress val[] is LSB-first, but BLE adv mfr data needs MSB-first MAC.
// Real lock: 59 44 E2 79 A5 DC 36 4D 00 02 0A
//   company: 59 44 (= 0x4459 LE)
//   MAC MSB first: E2 79 A5 DC 36 4D
// --------------------------------------------------------------------------
void buildMfrData(uint8_t *out11, const uint8_t *mac6_msb) {
  out11[0]=0x59; out11[1]=0x44;            // company ID 0x4459 LE
  out11[2]=mac6_msb[0]; out11[3]=mac6_msb[1]; out11[4]=mac6_msb[2];
  out11[5]=mac6_msb[3]; out11[6]=mac6_msb[4]; out11[7]=mac6_msb[5];
  out11[8]=0x00; out11[9]=0x02; out11[10]=0x0A; // status/devType=Wyze Lock
}

void startAdvertising() {
  NimBLEAdvertising *adv=NimBLEDevice::getAdvertising();
  adv->reset();
  adv->addServiceUUID(NUS_SERVICE_UUID);
  adv->addServiceUUID("180f");
  adv->setName("Wyze Lock");

  uint8_t mfrData[11];
  if(gUseLockMac) {
    // Use real lock's MAC -- keypad may validate MAC matches a known lock
    buildMfrData(mfrData, REAL_LOCK_MAC);
    addLog("r10b: Adv with REAL LOCK MAC: "+bytesToHex(REAL_LOCK_MAC,6));
  } else {
    // Use our own MAC (MSB-first corrected from NimBLE's LSB-first storage)
    NimBLEAddress ownAddr=NimBLEDevice::getAddress();
    const uint8_t *v=ownAddr.getBase()->val; // val[0]=LSB, val[5]=MSB
    uint8_t macMSB[6]={v[5],v[4],v[3],v[2],v[1],v[0]};
    buildMfrData(mfrData, macMSB);
    addLog("r10b: Adv with OWN MAC (MSB-first): "+bytesToHex(macMSB,6));
  }
  adv->setManufacturerData(std::string((char*)mfrData, 11));

  adv->setMinInterval(32); // 20ms
  adv->setMaxInterval(32); // 20ms tight -- maximize discovery speed

  bool ok=adv->start();
  addLog("Adv start: "+(ok?String("OK"):String("FAIL")));
  addLog("  Name: 'Wyze Lock'  NUS+Battery services");
  addLog("  Mfr:  "+bytesToHex(mfrData,11));
  addLog("  Own BLE addr: "+String(NimBLEDevice::getAddress().toString().c_str()));
}

void stopAdvertising(){NimBLEDevice::getAdvertising()->stop();addLog("Adv stopped");}

// --------------------------------------------------------------------------
// BLE peripheral setup
// --------------------------------------------------------------------------
void setupBlePeripheral() {
  addLog("r10b: Setup BLE peripheral (NUS server)");
  NimBLEDevice::setSecurityAuth(0);
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_NO_INPUT_OUTPUT);

  bleServer=NimBLEDevice::createServer();
  bleServer->setCallbacks(&gServerCB);

  nusService=bleServer->createService(NUS_SERVICE_UUID);

  rxChr=nusService->createCharacteristic(NUS_RX_UUID, NIMBLE_PROPERTY::WRITE|NIMBLE_PROPERTY::WRITE_NR);
  rxChr->setCallbacks(&gRxCharCB);

  txChr=nusService->createCharacteristic(NUS_TX_UUID, NIMBLE_PROPERTY::NOTIFY);
  txChr->setCallbacks(&gRxCharCB);

  nusService->start();
  addLog("  NUS RX (kp writes): "+String(NUS_RX_UUID));
  addLog("  NUS TX (we notify): "+String(NUS_TX_UUID));

  // Boost BT coex priority -- BLE peripheral needs consistent adv slots
  esp_coex_preference_set(ESP_COEX_PREFER_BT);
  addLog("  Coex -> BT priority for peripheral mode");

  startAdvertising();
}

// --------------------------------------------------------------------------
// Diagnostic scan
// --------------------------------------------------------------------------
bool isWyzeDevice(const NimBLEAdvertisedDevice *dev){
  if(dev->haveManufacturerData()){const std::string &m=dev->getManufacturerData();if(m.size()>=2&&(((uint8_t)m[0]|((uint8_t)m[1]<<8))==WYZE_COMPANY_ID))return true;}
  if(dev->haveName()){std::string n=dev->getName();for(int i=0;WYZE_ADV_NAMES[i];i++)if(n==WYZE_ADV_NAMES[i])return true;}
  return false;
}
void logWyzeMfrData(const NimBLEAdvertisedDevice *dev){
  if(!dev->haveManufacturerData())return;
  const std::string &m=dev->getManufacturerData(); size_t len=m.size();
  String hex; for(size_t i=0;i<len;i++){const char *h="0123456789ABCDEF";hex+=h[((uint8_t)m[i]>>4)&0xF];hex+=h[(uint8_t)m[i]&0xF];if(i+1<len)hex+=' ';}
  addLog("  mfr("+String(len)+"b): "+hex);
  if(len>=8){char ms[18];snprintf(ms,sizeof(ms),"%02X:%02X:%02X:%02X:%02X:%02X",(uint8_t)m[2],(uint8_t)m[3],(uint8_t)m[4],(uint8_t)m[5],(uint8_t)m[6],(uint8_t)m[7]);addLog("  -> MAC in adv: "+String(ms));}
  if(len>10){uint8_t dt=(uint8_t)m[10];addLog("  -> devType="+(dt==0x07?String("KP-01"):(dt==0x0A?String("Wyze Lock"):("0x"+String(dt,HEX)))));}
  if(len>11){uint8_t ps=(uint8_t)m[11];addLog("  -> byte11=0x"+String(ps,HEX)+(ps==0x0A?" (PAIRED?)":(ps==0x00?" (UNPAIRED?)":""))+" -- pairing mode indicator?");}
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
  addLog("Scan done: "+String(results.getCount())+" dev(s)");
  String json="[";bool first=true;
  for(int i=0;i<results.getCount();i++){
    const NimBLEAdvertisedDevice *dev=results.getDevice(i);
    NimBLEAddress addr=dev->getAddress();
    String addrStr=String(addr.toString().c_str());addrStr.toUpperCase();
    String name=dev->haveName()?String(dev->getName().c_str()):"";
    int rssi=dev->getRSSI();uint8_t at=addr.getType();
    String ats=(at==BLE_ADDR_RANDOM)?"random":"public";
    bool wyze=isWyzeDevice(dev);
    addLog("  "+addrStr+" ["+ats+"] '"+name+"' rssi="+String(rssi)+(wyze?" [Wyze]":""));
    if(wyze)logWyzeMfrData(dev);
    if(!first)json+=",";first=false;
    json+="{\"addr\":\""+jsonEscape(addrStr)+"\",\"addrType\":\""+ats+"\",\"name\":\""+jsonEscape(name)+"\",\"rssi\":"+String(rssi)+",\"wyze\":"+String(wyze?"true":"false")+"}";
  }
  json+="]";lastScanJson=json;
  scan->stop();scan->clearResults();
  scanRunning=false;
  esp_coex_preference_set(ESP_COEX_PREFER_BT); // keep BT priority
  if(!gAdvConnected){NimBLEDevice::getAdvertising()->start();addLog("Adv resumed");}
  return lastScanJson;
}

// --------------------------------------------------------------------------
// Packet helpers
// --------------------------------------------------------------------------
bool isBleReady(){return gAdvConnected&&txChr;}
bool sendPacket(const uint8_t *d,size_t l,const char *tag){return sendNotify(d,l,tag);}
bool sendRawHex(const String &hex){std::vector<uint8_t>buf;if(!parseHexString(hex,buf)){addLog("Hex parse fail: '"+hex+"'");return false;}return sendPacket(buf.data(),buf.size(),"RAW");}

static const uint8_t PKT_FF[8]    ={0xDE,0xC0,0xAD,0xDE,0xFF,0x01,0x1E,0xF1};
static const uint8_t PKT_FE[8]    ={0xDE,0xC0,0xAD,0xDE,0xFE,0x01,0x1E,0xF1};
static const uint8_t PKT_BIND[8]  ={0xDE,0xC0,0xAD,0xDE,0x01,0x1E,0xF1,0x00};
static const uint8_t PKT_UNLOCK[8]={0xDE,0xC0,0xAD,0xDE,0x00,0x01,0x1E,0xF1};
static const uint8_t PKT_KP[8]    ={0xDE,0xC0,0xAD,0xDE,0x02,0x01,0x1E,0xF1};

bool sendAuthResp(){
  if(!gNonceReceived){addLog("No nonce yet");return false;}
  uint8_t resp[8]={0};
  if(!computeAuthResponse(gLastNonce,resp)){addLog("AES failed");return false;}
  return sendNotify(resp,8,"AUTH_RESP_MANUAL");
}

// --------------------------------------------------------------------------
// State JSON
// --------------------------------------------------------------------------
String makeStateJson(){
  String json; json.reserve(4096);
  String ip=WiFi.status()==WL_CONNECTED?WiFi.localIP().toString():"";
  String apIp=portalMode?WiFi.softAPIP().toString():"";
  unsigned long tSinceConn=(gAdvConnected&&gConnectedAtMs)?(millis()-gConnectedAtMs):0;
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
  json+="\"tSinceConnMs\":"+String(tSinceConn)+",";
  json+="\"ownBleAddr\":\""+String(NimBLEDevice::getAddress().toString().c_str())+"\",";
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
  json+="}"; return json;
}

// --------------------------------------------------------------------------
// Web handlers
// --------------------------------------------------------------------------
void sendOk(const String &m){server.send(200,"application/json","{\"ok\":true,\"msg\":\""+jsonEscape(m)+"\"}");}
void sendErr(const String &m){server.send(200,"application/json","{\"ok\":false,\"msg\":\""+jsonEscape(m)+"\"}");}
bool argBool(const char *n,bool d){if(!server.hasArg(n))return d;String v=server.arg(n);v.toLowerCase();return v=="1"||v=="true"||v=="on"||v=="yes";}

void handleRoot()   {server.send_P(200,"text/html",INDEX_HTML);}
void handleState()  {server.send(200,"application/json",makeStateJson());}
void handleScan()   {server.send(200,"application/json",scanJson());}
void handleSaveConfig(){
  if(server.hasArg("bleAddress")){settings.bleAddress=server.arg("bleAddress");settings.bleAddress.trim();}
  if(server.hasArg("bleAddrType")){settings.bleAddrType=server.arg("bleAddrType");if(settings.bleAddrType!="random")settings.bleAddrType="public";}
  if(server.hasArg("bleName"))   settings.bleName    =server.arg("bleName");
  if(server.hasArg("serviceUuid")){settings.serviceUuid=server.arg("serviceUuid");settings.serviceUuid.trim();}
  if(server.hasArg("writeUuid")) {settings.writeUuid =server.arg("writeUuid"); settings.writeUuid.trim();}
  if(server.hasArg("notifyUuid")){settings.notifyUuid =server.arg("notifyUuid");settings.notifyUuid.trim();}
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

// Switch to advertising with real lock MAC (keypad may match on it)
void handleTryLockMac(){
  gUseLockMac=true;
  addLog("r10b: Switching to REAL LOCK MAC in adv: "+bytesToHex(REAL_LOCK_MAC,6));
  NimBLEDevice::getAdvertising()->stop();
  delay(100);
  startAdvertising();
  sendOk("Now advertising with real lock MAC: "+bytesToHex(REAL_LOCK_MAC,6)+" -- put keypad in pairing mode now");
}
// Switch back to own MAC
void handleUseOwnMac(){
  gUseLockMac=false;
  addLog("r10b: Switching back to OWN MAC in adv");
  NimBLEDevice::getAdvertising()->stop();
  delay(100);
  startAdvertising();
  sendOk("Now advertising with own MAC");
}

void handleSendFF()    {sendPacket(PKT_FF,   sizeof(PKT_FF),   "PROBE_FF")?sendOk("Sent"):sendErr("Failed");}
void handleSendFE()    {sendPacket(PKT_FE,   sizeof(PKT_FE),   "PROBE_FE")?sendOk("Sent"):sendErr("Failed");}
void handleSendBind()  {sendPacket(PKT_BIND, sizeof(PKT_BIND), "BIND")?sendOk("Sent"):sendErr("Failed");}
void handleSendUnlock(){sendPacket(PKT_UNLOCK,sizeof(PKT_UNLOCK),"UNLOCK")?sendOk("Sent"):sendErr("Failed");}
void handleSendKP()    {sendPacket(PKT_KP,   sizeof(PKT_KP),   "KEYPRESS")?sendOk("Sent"):sendErr("Failed");}
void handleSendRaw()   {sendRawHex(server.arg("hex"))?sendOk("Sent"):sendErr("Failed");}
void handleClearLog()  {logBuffer="";lastTxHex="";lastRxHex="";sendOk("Log cleared");}
void handleReboot()    {sendOk("Rebooting");delay(200);ESP.restart();}
void handleSendAuthResp(){sendAuthResp()?sendOk("Auth resp sent"):sendErr("Auth resp failed");}
void handleSendNotify() {sendRawHex(server.arg("hex"))?sendOk("Notify sent"):sendErr("Failed");}

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
  server.begin();addLog("HTTP server started");
}

void serviceWiFi(){
  bool up=(WiFi.status()==WL_CONNECTED);
  if(up&&!wifiWasConnected){wifiWasConnected=true;addLog("WiFi up: "+WiFi.localIP().toString());ensureMDNSOTA();stopPortal();}
  if(!up&&wifiWasConnected){wifiWasConnected=false;addLog("WiFi down");lastWifiTryMs=millis();}
  if(!up){if(millis()-lastWifiTryMs>15000)beginWiFi(portalMode);if(!portalMode&&millis()>30000&&millis()-lastWifiTryMs>10000)startPortal();}
}

void setup(){
  DBG_BEGIN(115200);delay(200);addLog("Boot r10b");
  loadSettings();
  addLog("AES key: "+bytesToHex(AES_KEY,16));
  addLog("Real lock MAC: "+bytesToHex(REAL_LOCK_MAC,6));
  addLog("r10b: MODE = BLE PERIPHERAL");
  WiFi.disconnect(true,true);delay(200);
  beginWiFi(false);
  NimBLEDevice::init("Wyze Lock");
  NimBLEDevice::setPower(9);
  NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_RANDOM);
  addLog("Own BLE addr: "+String(NimBLEDevice::getAddress().toString().c_str()));
  NimBLEDevice::setSecurityAuth(0);
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_NO_INPUT_OUTPUT);
  addLog("NimBLE init done");
  setupBlePeripheral();
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
  serviceWiFi();serviceMQTT();
  if(millis()-lastStateMs>10000){
    lastStateMs=millis();
    addLog("State wifi="+String(WiFi.status()==WL_CONNECTED?"up":"down")
           +" ble="+String(gAdvConnected?"CONNECTED":"advertising")
           +" lockMac="+String(gUseLockMac?"yes":"no")
           +" nonce="+String(gNonceReceived?"yes":"waiting")
           +" tSinceConn="+String((gAdvConnected&&gConnectedAtMs)?(millis()-gConnectedAtMs):0)+"ms");
  }
  delay(5);
}
