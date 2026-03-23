#pragma once

const char INDEX_HTML[] PROGMEM = R"HTML(
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WKPbridge</title>
<style>
body{font-family:system-ui,Arial,sans-serif;background:#111;color:#eee;margin:0;padding:16px}
h1,h2{margin:.2em 0}
.card{background:#1b1b1b;border:1px solid #333;border-radius:10px;padding:12px;margin:10px 0}
label{display:block;margin:8px 0 4px}
input,button,textarea{width:100%;box-sizing:border-box;padding:8px;border-radius:8px;border:1px solid #444;background:#222;color:#eee}
button{cursor:pointer;background:#2e5}
button.alt{background:#444}
button.warn{background:#b55}
.row{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.small{font-size:.9em;color:#bbb}
pre{white-space:pre-wrap;word-wrap:break-word;background:#0d0d0d;border:1px solid #333;border-radius:8px;padding:10px;min-height:80px;max-height:280px;overflow:auto}
.status{font-family:monospace}
a{color:#8cf}
</style>
</head>
<body>
<h1>WKPbridge</h1>
<div class="small">ESP32-C3 BLE bridge / packet test UI</div>

<div class="card">
  <h2>Status</h2>
  <div id="status" class="status">Loading...</div>
  <div class="row">
    <button onclick="refreshState()">Refresh</button>
    <button class="warn" onclick="postOnly('/api/reboot')">Reboot</button>
  </div>
</div>

<div class="card">
  <h2>WiFi</h2>
  <label>SSID</label>
  <input id="ssid">
  <label>Password</label>
  <input id="psk" type="password">
  <div class="row">
    <button onclick="saveWifi()">Save WiFi</button>
    <button class="alt" onclick="togglePsk()">Show/Hide</button>
  </div>
  <div class="small">If STA fails, this page is also served from the AP captive portal.</div>
</div>

<div class="card">
  <h2>BLE config</h2>
  <label>Target BLE address</label>
  <input id="bleAddress" placeholder="AA:BB:CC:DD:EE:FF">
  <label>Target name contains</label>
  <input id="bleName" placeholder="optional fallback match">
  <label>Service UUID</label>
  <input id="serviceUuid" placeholder="0000xxxx-0000-1000-8000-00805f9b34fb">
  <label>Write characteristic UUID</label>
  <input id="writeUuid">
  <label>Notify characteristic UUID</label>
  <input id="notifyUuid">
  <div class="row">
    <div>
      <label><input id="autoConnect" type="checkbox" style="width:auto"> Auto connect</label>
    </div>
    <div>
      <label><input id="writeWithResponse" type="checkbox" style="width:auto"> Write with response</label>
    </div>
  </div>
  <label>Scan seconds</label>
  <input id="scanSeconds" type="number" min="1" max="20">
  <div class="row">
    <button onclick="saveConfig()">Save config</button>
    <button class="alt" onclick="scanNow()">Scan</button>
  </div>
  <div class="row">
    <button onclick="postOnly('/api/connect')">Connect</button>
    <button class="alt" onclick="postOnly('/api/disconnect')">Disconnect</button>
  </div>
</div>

<div class="card">
  <h2>Known packets</h2>
  <div class="small">FF = DE C0 AD DE FF 01 1E F1</div>
  <div class="small">FE = DE C0 AD DE FE 01 1E F1</div>
  <div class="row" style="margin-top:8px">
    <button onclick="postOnly('/api/sendFF')">Send FF</button>
    <button onclick="postOnly('/api/sendFE')">Send FE</button>
  </div>
  <label>Raw hex</label>
  <input id="rawHex" placeholder="DE C0 AD DE FF 01 1E F1">
  <button onclick="sendRaw()">Send raw</button>
</div>

<div class="card">
  <h2>Scan results</h2>
  <pre id="scanBox"></pre>
</div>

<div class="card">
  <h2>Logs</h2>
  <div class="row">
    <button class="alt" onclick="refreshState()">Refresh logs</button>
    <button class="warn" onclick="postOnly('/api/clearLog')">Clear logs</button>
  </div>
  <pre id="logs"></pre>
</div>

<script>
async function jget(url){
  const r = await fetch(url,{cache:'no-store'});
  return await r.json();
}
async function jpost(url,obj={}){
  const body = new URLSearchParams(obj);
  const r = await fetch(url,{method:'POST',body});
  return await r.json();
}
function setv(id,v){ document.getElementById(id).value = v ?? ''; }
function setc(id,v){ document.getElementById(id).checked = !!v; }
function esc(s){
  return (s ?? '').toString();
}
function togglePsk(){
  const e = document.getElementById('psk');
  e.type = e.type === 'password' ? 'text' : 'password';
}
async function refreshState(){
  try{
    const s = await jget('/api/state');
    document.getElementById('status').textContent =
      'wifi=' + (s.wifiConnected?'up':'down') +
      ' ip=' + (s.ip||'-') +
      ' ap=' + (s.portalMode ? (s.apIp||'on') : 'off') +
      ' rssi=' + s.rssi +
      ' ble=' + (s.bleConnected?'up':'down') +
      ' peer=' + (s.blePeer||'-') +
      ' host=' + s.hostname + '.local';

    setv('ssid', s.ssid);
    setv('bleAddress', s.bleAddress);
    setv('bleName', s.bleName);
    setv('serviceUuid', s.serviceUuid);
    setv('writeUuid', s.writeUuid);
    setv('notifyUuid', s.notifyUuid);
    setv('scanSeconds', s.scanSeconds);
    setc('autoConnect', s.autoConnect);
    setc('writeWithResponse', s.writeWithResponse);

    document.getElementById('logs').textContent = s.logs || '';
    document.getElementById('scanBox').textContent = JSON.stringify(s.scan || [], null, 2);
  }catch(e){
    document.getElementById('status').textContent = 'State fetch failed: ' + e;
  }
}
async function saveWifi(){
  const res = await jpost('/api/saveWifi',{
    ssid: document.getElementById('ssid').value,
    psk: document.getElementById('psk').value
  });
  alert(res.msg || (res.ok ? 'OK' : 'Fail'));
  setTimeout(refreshState, 500);
}
async function saveConfig(){
  const res = await jpost('/api/saveConfig',{
    bleAddress: document.getElementById('bleAddress').value,
    bleName: document.getElementById('bleName').value,
    serviceUuid: document.getElementById('serviceUuid').value,
    writeUuid: document.getElementById('writeUuid').value,
    notifyUuid: document.getElementById('notifyUuid').value,
    autoConnect: document.getElementById('autoConnect').checked ? '1' : '0',
    writeWithResponse: document.getElementById('writeWithResponse').checked ? '1' : '0',
    scanSeconds: document.getElementById('scanSeconds').value
  });
  alert(res.msg || (res.ok ? 'OK' : 'Fail'));
  setTimeout(refreshState, 300);
}
async function scanNow(){
  const data = await jget('/api/scan');
  document.getElementById('scanBox').textContent = JSON.stringify(data, null, 2);
}
async function sendRaw(){
  const res = await jpost('/api/sendRaw',{
    hex: document.getElementById('rawHex').value
  });
  alert(res.msg || (res.ok ? 'OK' : 'Fail'));
  setTimeout(refreshState, 300);
}
async function postOnly(url){
  const res = await jpost(url,{});
  alert(res.msg || (res.ok ? 'OK' : 'Fail'));
  setTimeout(refreshState, 500);
}
setInterval(refreshState, 2000);
refreshState();
</script>
</body>
</html>
)HTML";