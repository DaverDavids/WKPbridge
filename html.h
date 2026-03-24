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
button{cursor:pointer;background:#2e5;color:#000;font-weight:bold}
button.alt{background:#444;color:#eee;font-weight:normal}
button.warn{background:#b55;color:#fff}
button.sm{padding:4px 10px;width:auto;font-size:.85em}
button.probe{background:#295;color:#fff}
button.bind{background:#256;color:#fff}
button.unlock{background:#52a;color:#fff}
.row{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.row3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px}
.small{font-size:.9em;color:#bbb}
pre{white-space:pre-wrap;word-wrap:break-word;background:#0d0d0d;border:1px solid #333;border-radius:8px;padding:10px;min-height:60px;max-height:340px;overflow:auto;font-size:.82em;font-family:monospace}
.status{font-family:monospace;font-size:.9em;padding:6px;background:#0d0d0d;border-radius:6px}
.devlist{list-style:none;padding:0;margin:0}
.devlist li{display:flex;align-items:center;justify-content:space-between;padding:7px 8px;border-bottom:1px solid #2a2a2a;font-family:monospace;font-size:.88em}
.devlist li:last-child{border-bottom:none}
.devlist li:hover{background:#222}
.pill{display:inline-block;padding:2px 8px;border-radius:9px;font-size:.78em;font-weight:bold;margin-left:6px}
.pill.up{background:#1a4}
.pill.down{background:#622}
.pill.wyze{background:#256;color:#9cf}
.scanning{color:#fa0;font-style:italic}
.dirty{border-color:#fa0 !important}
.rxbox{font-family:monospace;background:#0a1a0a;border:1px solid #2a4a2a;border-radius:8px;padding:8px;min-height:36px;word-break:break-all;color:#8f8}
.txlabel{color:#fa0;font-weight:bold}
.rxlabel{color:#8f8;font-weight:bold}
</style>
</head>
<body>
<h1>WKPbridge <span class="small" id="rev" style="font-size:.5em;font-weight:normal">r7</span></h1>
<div class="small">ESP32-C3 &bull; Wyze Keypad BLE bridge</div>

<!-- STATUS -->
<div class="card">
  <h2>Status</h2>
  <div id="status" class="status">Loading...</div>
  <div style="margin-top:8px" class="row">
    <button class="alt" onclick="pollStatus()">Refresh</button>
    <button class="warn" onclick="postCmd('/api/reboot')">Reboot</button>
  </div>
</div>

<!-- WIFI -->
<div class="card">
  <h2>WiFi</h2>
  <label>SSID</label>
  <input id="ssid" autocomplete="off">
  <label>Password</label>
  <input id="psk" type="password" autocomplete="new-password">
  <div class="row" style="margin-top:8px">
    <button onclick="saveWifi()">Save &amp; Connect</button>
    <button class="alt" onclick="togglePsk()">Show / Hide</button>
  </div>
</div>

<!-- BLE SCAN -->
<div class="card">
  <h2>BLE Scan</h2>
  <div class="small" style="margin-bottom:6px">Scans for: <b>Wyze Lock</b>, <b>DingDing</b>, <b>KP-01</b>, <b>DD-Fact</b>, or any Wyze mfr-id device.</div>
  <div class="row">
    <button onclick="scanNow()" id="scanBtn">Scan for devices</button>
    <label style="margin:0;display:flex;align-items:center;gap:6px">
      <input id="scanSeconds" type="number" min="1" max="20" style="width:52px;padding:6px"> sec
    </label>
  </div>
  <div id="scanStatus" class="small" style="margin-top:6px"></div>
  <ul class="devlist" id="devlist" style="margin-top:8px"></ul>
  <div class="small" style="margin-top:4px">Click <b>Select</b> to fill BLE config, then <b>Save config</b> &rarr; <b>Connect</b>.</div>
</div>

<!-- BLE CONFIG -->
<div class="card">
  <h2>BLE config
    <span class="small" style="font-weight:normal;font-size:.7em;margin-left:8px" id="configDirtyLabel"></span>
  </h2>
  <label>Target BLE address</label>
  <input id="bleAddress" placeholder="AA:BB:CC:DD:EE:FF" autocomplete="off" oninput="markDirty()">
  <label>Address type</label>
  <select id="bleAddrType" style="width:100%;box-sizing:border-box;padding:8px;border-radius:8px;border:1px solid #444;background:#222;color:#eee" onchange="markDirty()">
    <option value="public">Public</option>
    <option value="random">Random</option>
  </select>
  <label>Target name filter <span class="small">(fallback if no address — Wyze names auto-matched)</span></label>
  <input id="bleName" placeholder="Wyze Lock" autocomplete="off" oninput="markDirty()">
  <label>Service UUID <span class="small">(Wyze: 0000fe50-…)</span></label>
  <input id="serviceUuid" autocomplete="off" oninput="markDirty()">
  <label>Write (RX) characteristic UUID <span class="small">(Wyze: 0000fe51-…)</span></label>
  <input id="writeUuid" autocomplete="off" oninput="markDirty()">
  <label>Notify (TX) characteristic UUID <span class="small">(Wyze: 0000fe52-…)</span></label>
  <input id="notifyUuid" autocomplete="off" oninput="markDirty()">
  <div class="row" style="margin-top:8px">
    <label style="margin:0;display:flex;align-items:center;gap:6px;cursor:pointer">
      <input id="autoConnect" type="checkbox" style="width:auto" onchange="markDirty()"> Auto-connect on boot
    </label>
    <label style="margin:0;display:flex;align-items:center;gap:6px;cursor:pointer">
      <input id="writeWithResponse" type="checkbox" style="width:auto" onchange="markDirty()"> Write with response
    </label>
  </div>
  <div class="row" style="margin-top:10px">
    <button onclick="saveConfig()" id="saveConfigBtn">Save config</button>
    <button class="alt" onclick="reloadConfig()">Reload from device</button>
  </div>
  <div class="row" style="margin-top:6px">
    <button onclick="postCmd('/api/connect')">Connect</button>
    <button class="alt" onclick="postCmd('/api/disconnect')">Disconnect</button>
  </div>
  <div class="row" style="margin-top:6px">
    <button class="alt" onclick="postCmd('/api/clearBonds')">Clear bonds</button>
    <button class="alt" onclick="postCmd('/api/gattDump')">GATT dump (log)</button>
  </div>
</div>

<!-- SEND PACKETS -->
<div class="card">
  <h2>Send packets</h2>

  <div class="small" style="margin-bottom:6px">Header: <code>DE C0 AD DE</code> &bull; byte[4]=opcode &bull; bytes[5-7]=payload</div>

  <table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:.85em;margin-bottom:10px">
    <tr style="color:#888"><th style="text-align:left;padding:3px 6px">Button</th><th style="text-align:left;padding:3px 6px">Hex</th><th style="text-align:left;padding:3px 6px">Purpose</th></tr>
    <tr><td style="padding:3px 6px">Probe FF</td><td><code>DE C0 AD DE FF 01 1E F1</code></td><td>identify / wake</td></tr>
    <tr><td style="padding:3px 6px">Probe FE</td><td><code>DE C0 AD DE FE 01 1E F1</code></td><td>probe alt</td></tr>
    <tr><td style="padding:3px 6px">Bind</td><td><code>DE C0 AD DE 01 1E F1 00</code></td><td>MSGKEYPADBIND</td></tr>
    <tr><td style="padding:3px 6px">Unlock</td><td><code>DE C0 AD DE 00 01 1E F1</code></td><td>MSGKEYPADUNLOCK</td></tr>
    <tr><td style="padding:3px 6px">Keypress</td><td><code>DE C0 AD DE 02 01 1E F1</code></td><td>MSGKEYPADPRESS</td></tr>
  </table>

  <div class="row" style="margin-bottom:6px">
    <button class="probe" onclick="postCmd('/api/sendFF')">Probe FF</button>
    <button class="probe" onclick="postCmd('/api/sendFE')">Probe FE</button>
  </div>
  <div class="row3" style="margin-bottom:6px">
    <button class="bind" onclick="postCmd('/api/sendBind')">Bind</button>
    <button class="unlock" onclick="postCmd('/api/sendUnlock')">Unlock</button>
    <button class="alt" onclick="postCmd('/api/sendKP')">Keypress</button>
  </div>

  <label style="margin-top:8px">Raw hex bytes <span class="small">(space/colon/comma separated)</span></label>
  <div style="display:flex;gap:6px">
    <input id="rawHex" placeholder="DE C0 AD DE FF 01 1E F1" autocomplete="off" style="flex:1">
    <button style="width:auto;padding:8px 14px" onclick="sendRaw()">Send</button>
  </div>
  <button class="alt sm" style="margin-top:4px" onclick="fillRawFromRx()">Fill from last RX &uarr;</button>

  <div style="margin-top:10px">
    <span class="txlabel">TX:</span> <span id="lastTx" style="font-family:monospace;color:#fa0">-</span>
  </div>
  <div style="margin-top:6px">
    <span class="rxlabel">RX:</span>
    <div class="rxbox" id="lastRxBox">-</div>
  </div>
</div>

<!-- LOGS -->
<div class="card">
  <h2>Logs</h2>
  <div class="row">
    <button class="alt" onclick="pollStatus()">Refresh logs</button>
    <button class="warn" onclick="postCmd('/api/clearLog')">Clear logs</button>
  </div>
  <label style="margin-top:6px;display:flex;align-items:center;gap:8px">
    <input id="autoScroll" type="checkbox" style="width:auto" checked> Auto-scroll
  </label>
  <pre id="logs" style="margin-top:8px"></pre>
</div>

<script>
async function jget(url){
  const r=await fetch(url,{cache:'no-store'});
  return await r.json();
}
async function jpost(url,obj={}){
  const r=await fetch(url,{method:'POST',body:new URLSearchParams(obj)});
  return await r.json();
}
function el(id){return document.getElementById(id);}
function escHtml(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function togglePsk(){const e=el('psk');e.type=e.type==='password'?'text':'password';}

let configDirty=false;
function markDirty(){
  if(!configDirty){configDirty=true;el('saveConfigBtn').style.background='#fa0';el('configDirtyLabel').textContent='(unsaved changes)';}
}
function clearDirty(){
  configDirty=false;el('saveConfigBtn').style.background='';el('configDirtyLabel').textContent='';
}

let configLoaded=false;
function applyConfig(s){
  el('bleAddress').value          =s.bleAddress    ||'';
  el('bleAddrType').value         =s.bleAddrType   ||'random';
  el('bleName').value             =s.bleName       ||'';
  el('serviceUuid').value         =s.serviceUuid   ||'';
  el('writeUuid').value           =s.writeUuid     ||'';
  el('notifyUuid').value          =s.notifyUuid    ||'';
  el('scanSeconds').value         =s.scanSeconds   ||5;
  el('autoConnect').checked       =!!s.autoConnect;
  el('writeWithResponse').checked =!!s.writeWithResponse;
  el('ssid').value                =s.ssid          ||'';
  clearDirty();
  configLoaded=true;
}

async function reloadConfig(){
  try{
    const s=await jget('/api/state');
    applyConfig(s);
  }catch(e){alert('Reload failed: '+e);}
}

let lastRxHex='';
async function pollStatus(){
  try{
    const s=await jget('/api/state');
    if(!configLoaded)applyConfig(s);
    const wUp=s.wifiConnected,bUp=s.bleConnected;
    el('status').innerHTML=
      'WiFi <span class="pill '+(wUp?'up':'down')+'">'+(wUp?'UP':'DOWN')+'</span> '+
      (wUp?s.ip:(s.portalMode?'AP '+s.apIp:'no IP'))+
      (wUp?' rssi='+s.rssi:'')+' &nbsp; '+
      'BLE <span class="pill '+(bUp?'up':'down')+'">'+(bUp?'UP':'DOWN')+'</span> '+
      (bUp?escHtml(s.blePeer):'not connected')+' &nbsp; '+
      '<span class="small">'+escHtml(s.hostname)+'.local</span>';
    el('lastTx').textContent=s.lastTx||'-';
    if(s.lastRx && s.lastRx!==lastRxHex){
      lastRxHex=s.lastRx;
      el('lastRxBox').textContent=s.lastRx;
      el('lastRxBox').style.borderColor='#4f4';
      setTimeout(()=>{el('lastRxBox').style.borderColor='';},1500);
    }
    const logEl=el('logs');
    const autoScroll=el('autoScroll').checked;
    const atBottom=logEl.scrollHeight-logEl.scrollTop<=logEl.clientHeight+40;
    logEl.textContent=s.logs||'';
    if(autoScroll||(atBottom))logEl.scrollTop=logEl.scrollHeight;
  }catch(e){
    el('status').textContent='Poll error: '+e;
  }
}

async function scanNow(){
  const btn=el('scanBtn');
  btn.disabled=true;btn.textContent='Scanning…';
  el('scanStatus').textContent='Scanning for '+el('scanSeconds').value+'s…';
  el('scanStatus').className='small scanning';
  el('devlist').innerHTML='';
  try{
    const devs=await jget('/api/scan');
    renderDevList(devs);
    el('scanStatus').textContent=devs.length+' device(s) found.';
    el('scanStatus').className='small';
  }catch(e){
    el('scanStatus').textContent='Scan error: '+e;
    el('scanStatus').className='small';
  }
  btn.disabled=false;btn.textContent='Scan for devices';
}

function renderDevList(devs){
  const ul=el('devlist');
  ul.innerHTML='';
  if(!devs||devs.length===0){
    ul.innerHTML='<li><span class="small">No devices found. Put keypad in pairing mode (hold * or # depending on state).</span></li>';
    return;
  }
  devs.sort((a,b)=>b.rssi-a.rssi);
  devs.forEach(d=>{
    const li=document.createElement('li');
    const name=d.name||'<no name>';
    const atype=d.addrType||'public';
    const wyzeBadge=d.wyze?'<span class="pill wyze">Wyze</span>':'';
    li.innerHTML=
      '<span style="color:#8ef;font-weight:bold;flex:1">'+escHtml(name)+wyzeBadge+'</span>'+
      '<span style="color:#aaa;flex:1;text-align:center">'+escHtml(d.addr)+'</span>'+
      '<span style="color:#888;width:4em;text-align:right">'+d.rssi+'dB</span>'+
      '<span style="color:#666;width:4em;text-align:right;font-size:.8em">'+atype+'</span>'+
      '<button class="sm alt" style="margin-left:8px;flex-shrink:0">Select</button>';
    li.querySelector('button').addEventListener('click',()=>{
      el('bleAddress').value=d.addr;
      el('bleAddrType').value=atype;
      markDirty();
      ul.querySelectorAll('li').forEach(x=>x.style.background='');
      li.style.background='#1a3a1a';
      el('scanStatus').textContent='Selected: '+d.addr+' ('+atype+') — '+name+'. Save config → Connect.';
    });
    ul.appendChild(li);
  });
}

async function saveWifi(){
  const res=await jpost('/api/saveWifi',{ssid:el('ssid').value,psk:el('psk').value});
  alert(res.msg||(res.ok?'OK':'Fail'));
  setTimeout(pollStatus,800);
}

async function saveConfig(){
  const res=await jpost('/api/saveConfig',{
    bleAddress:        el('bleAddress').value,
    bleAddrType:       el('bleAddrType').value,
    bleName:           el('bleName').value,
    serviceUuid:       el('serviceUuid').value,
    writeUuid:         el('writeUuid').value,
    notifyUuid:        el('notifyUuid').value,
    autoConnect:       el('autoConnect').checked?'1':'0',
    writeWithResponse: el('writeWithResponse').checked?'1':'0',
    scanSeconds:       el('scanSeconds').value
  });
  if(res.ok)clearDirty();
  alert(res.msg||(res.ok?'Saved':'Fail'));
}

async function sendRaw(){
  const res=await jpost('/api/sendRaw',{hex:el('rawHex').value});
  alert(res.msg||(res.ok?'OK':'Fail'));
  setTimeout(pollStatus,300);
}

function fillRawFromRx(){
  if(lastRxHex){el('rawHex').value=lastRxHex;}
}

async function postCmd(url){
  const res=await jpost(url,{});
  alert(res.msg||(res.ok?'OK':'Fail'));
  setTimeout(pollStatus,600);
}

pollStatus();
setInterval(pollStatus,3000);
</script>
</body>
</html>
)HTML";
