#pragma once
#include <pgmspace.h>

static const char INDEX_HTML[] PROGMEM = R"HTMLEOF(
<!DOCTYPE html><html><head>
<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>WKPbridge</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;background:#1a1a1a;color:#e0e0e0;padding:10px;font-size:13px}
h2{color:#4af;margin:8px 0 4px}
.card{background:#252525;border:1px solid #333;border-radius:6px;padding:10px;margin-bottom:10px}
.row{display:flex;flex-wrap:wrap;gap:6px;margin:4px 0}
button{background:#2a5a8a;color:#fff;border:none;padding:5px 10px;border-radius:4px;cursor:pointer;font-family:monospace;font-size:12px}
button:hover{background:#3a7ac0}
button.red{background:#8a2a2a}button.red:hover{background:#c03a3a}
button.grn{background:#2a6a2a}button.grn:hover{background:#3a9a3a}
button.ylw{background:#6a5a00}button.ylw:hover{background:#9a8000}
input,select{background:#333;color:#e0e0e0;border:1px solid #555;padding:4px 6px;border-radius:4px;font-family:monospace;font-size:12px}
.log{background:#111;border:1px solid #333;padding:6px;height:200px;overflow-y:auto;white-space:pre;font-size:11px;border-radius:4px}
.term{background:#000;border:1px solid #0a0;padding:6px;height:240px;overflow-y:auto;white-space:pre;font-size:11px;color:#0f0;border-radius:4px;font-family:'Courier New',monospace}
.status{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px}
.on{background:#1a4a1a;color:#4f4}.off{background:#4a1a1a;color:#f44}
label{color:#aaa;font-size:11px}
</style>
</head><body>
<h2>WKPbridge <span id='ver' style='font-size:11px;color:#888'>r10h</span></h2>

<div class='card'>
  <h2>Status</h2>
  <div class='row'>
    <span>WiFi: <span id='wifiSt' class='status off'>--</span></span>
    <span>BLE: <span id='bleSt' class='status off'>--</span></span>
    <span>Nonce: <span id='nonceSt' class='status off'>--</span></span>
    <span>UART1: <span id='uartSt' class='status off'>--</span></span>
  </div>
  <div style='margin-top:4px;color:#888;font-size:11px' id='statusLine'>-</div>
</div>

<div class='card'>
  <h2>BLE Actions</h2>
  <div class='row'>
    <button onclick='post("/api/connect")'>Connect</button>
    <button class='red' onclick='post("/api/disconnect")'>Disconnect</button>
    <button onclick='post("/api/sendAuthResp")'>Send Auth Resp</button>
    <button onclick='post("/api/sendFF")'>FF</button>
    <button onclick='post("/api/sendFE")'>FE</button>
    <button onclick='post("/api/sendBind")'>Bind</button>
    <button onclick='post("/api/sendUnlock")'>Unlock</button>
    <button onclick='post("/api/sendKP")'>KP</button>
    <button class='red' onclick='post("/api/clearBonds")'>Clear Bonds</button>
  </div>
  <div class='row' style='margin-top:4px'>
    <label>Raw hex:</label>
    <input id='rawHex' size='30' placeholder='DE C0 AD DE FF...'>
    <button onclick='sendRaw()'>Send Raw</button>
  </div>
</div>

<div class='card'>
  <h2>UART1 Serial Terminal &nbsp;<span style='font-size:10px;color:#888'>RX=GPIO20 &nbsp; TX=GPIO21</span></h2>
  <div class='row'>
    <label>Baud:</label>
    <select id='baudSel'>
      <option>9600</option><option>19200</option><option>38400</option>
      <option>57600</option><option selected>115200</option>
      <option>230400</option><option>460800</option><option>921600</option>
      <option>1000000</option><option>1500000</option><option>2000000</option>
    </select>
    <label>Format:</label>
    <select id='cfgSel'>
      <option>8N1</option><option>8E1</option><option>8O1</option>
      <option>7N1</option><option>7E1</option><option>7O1</option>
    </select>
    <label>Mode:</label>
    <select id='hexSel'><option value='0'>ASCII</option><option value='1'>Hex dump</option></select>
    <button class='grn' onclick='serialOpen()'>Open</button>
    <button class='red' onclick='serialClose()'>Close</button>
    <button class='ylw' onclick='serialClear()'>Clear</button>
  </div>
  <div id='term' class='term'></div>
  <div class='row' style='margin-top:4px'>
    <input id='serialTxt' size='30' placeholder='text to send'>
    <button onclick='serialSendTxt()'>Send Text</button>
    <input id='serialHex' size='20' placeholder='hex bytes'>
    <button onclick='serialSendHex()'>Send Hex</button>
  </div>
</div>

<div class='card'>
  <h2>Log <button style='float:right;font-size:10px' onclick='post("/api/clearLog")'>Clear</button></h2>
  <div id='log' class='log'></div>
</div>

<div class='card'>
  <h2>Config</h2>
  <div class='row'>
    <label>WiFi SSID:</label><input id='ssid' size='20'>
    <label>PSK:</label><input id='psk' size='20' type='password'>
    <button onclick='saveWifi()'>Save WiFi</button>
  </div>
  <div class='row' style='margin-top:4px'>
    <button onclick='post("/api/reboot")' class='red'>Reboot</button>
    <button onclick='doScan()'>BLE Scan</button>
  </div>
</div>

<script>
let autoScroll=true, termAutoScroll=true;
const log=document.getElementById('log');
const term=document.getElementById('term');

function post(url,body){
  const opts={method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'}};
  if(body)opts.body=body;
  fetch(url,opts).then(r=>r.json()).then(d=>{
    appendLog('[POST '+url+'] '+(d.ok?'OK':'ERR')+': '+d.msg);
  }).catch(e=>appendLog('[POST '+url+'] '+e));
}
function appendLog(s){
  log.textContent+=s+'\n';
  if(autoScroll)log.scrollTop=log.scrollHeight;
}
function appendTerm(s){
  term.textContent+=s;
  if(termAutoScroll)term.scrollTop=term.scrollHeight;
}

function sendRaw(){post('/api/sendRaw','hex='+encodeURIComponent(document.getElementById('rawHex').value));}
function saveWifi(){post('/api/saveWifi','ssid='+encodeURIComponent(document.getElementById('ssid').value)+'&psk='+encodeURIComponent(document.getElementById('psk').value));}
function doScan(){
  appendLog('Starting scan...');
  fetch('/api/scan').then(r=>r.json()).then(d=>{
    appendLog('Scan: '+JSON.stringify(d));
  });
}

// UART1
function serialOpen(){
  const baud=document.getElementById('baudSel').value;
  const cfg=document.getElementById('cfgSel').value;
  const hex=document.getElementById('hexSel').value;
  post('/api/serial/config','baud='+baud+'&cfg='+cfg+'&hex='+hex);
}
function serialClose(){post('/api/serial/close');}
function serialClear(){
  post('/api/serial/clear');
  term.textContent='';
}
function serialSendTxt(){
  const t=document.getElementById('serialTxt').value;
  post('/api/serial/write','txt='+encodeURIComponent(t));
}
function serialSendHex(){
  const h=document.getElementById('serialHex').value;
  post('/api/serial/write','hex='+encodeURIComponent(h));
}

let lastPollData='';
function pollSerial(){
  fetch('/api/serial/read').then(r=>r.json()).then(d=>{
    if(d.data&&d.data.length>0) appendTerm(d.data);
  }).catch(()=>{});
}

function refreshState(){
  fetch('/api/state').then(r=>r.json()).then(d=>{
    document.getElementById('wifiSt').textContent=d.wifiConnected?d.ip:'OFF';
    document.getElementById('wifiSt').className='status '+(d.wifiConnected?'on':'off');
    document.getElementById('bleSt').textContent=d.bleConnected?'CONN':'OFF';
    document.getElementById('bleSt').className='status '+(d.bleConnected?'on':'off');
    document.getElementById('nonceSt').textContent=d.nonceReceived?'YES':'wait';
    document.getElementById('nonceSt').className='status '+(d.nonceReceived?'on':'off');
    document.getElementById('uartSt').textContent=d.uart1Open?(d.uart1Baud+'bd'):'closed';
    document.getElementById('uartSt').className='status '+(d.uart1Open?'on':'off');
    let sl='';
    if(d.bleConnected)sl+='KP: '+d.keypadMac+'  t+'+d.tSinceConnMs+'ms  ';
    if(d.nonceReceived)sl+='nonce: '+d.lastNonce+'  ';
    if(d.lastTx)sl+='TX: '+d.lastTx+'  ';
    if(d.lastRx)sl+='RX: '+d.lastRx;
    document.getElementById('statusLine').textContent=sl||'--';
    // update log
    if(d.logs){
      log.textContent=d.logs;
      if(autoScroll)log.scrollTop=log.scrollHeight;
    }
    // pre-fill ssid
    if(!document.getElementById('ssid').value&&d.ssid)
      document.getElementById('ssid').value=d.ssid;
  }).catch(()=>{});
}

setInterval(refreshState,2000);
setInterval(pollSerial, 500);
refreshState();
</script>
</body></html>
)HTMLEOF";
