const svcs = {
  vitals: { status: 'healthy', port: 5000, crit: true, reqs: 0 },
  'drug-dispenser': { status: 'healthy', port: 5001, crit: true, reqs: 0 },
  ehr: { status: 'healthy', port: 5002, crit: false, reqs: 0 },
  billing: { status: 'healthy', port: 5003, crit: false, reqs: 0 }
};

let metrics = { ev: 0, al: 0, mttd: [], mttr: [], fp: 0, tp: 0, start: null };
let state = { running: true, attack: false, stage: -1, ctr: 0, hist: [] };

const ATK = [
  { n: 'Initial Access', sc: 'sys_execve', tgt: '/bin/sh', sc_e: 2, f_e: 8, p_e: 800, port: 0 },
  { n: 'Lateral Move', sc: 'sys_connect', tgt: 'billing:445', sc_e: 0, f_e: 8, p_e: 50, port: 445 },
  { n: 'Encryption', sc: 'sys_rename', tgt: 'patient.locked', sc_e: 3, f_e: 1, p_e: 10, port: 0 },
  { n: 'Exfiltration', sc: 'sys_connect', tgt: 'c2.com', sc_e: 0, f_e: 8, p_e: 63, port: 53 }
];

function r(id) { return document.getElementById(id); }

function renderSvcs() {
  let h = '';
  for (const [k, v] of Object.entries(svcs)) {
    h += `<div class="sc ${v.status}"><div class="sn">${k}</div><span class="sb ${v.status}">${v.status}</span>
    ${v.crit ? '<div class="scrit">⚠ Critical</div>' : ''}<div class="sm">Port ${v.port} · ${v.reqs} reqs</div></div>`;
  }
  r('svcGrid').innerHTML = h;
}

function updateMetrics() {
  r('mEv').innerText = metrics.ev; r('mAl').innerText = metrics.al;
  const avg = a => a.length ? (a.reduce((x,y)=>x+y)/a.length).toFixed(1) : '—';
  r('mMTTD').innerText = avg(metrics.mttd); r('mMTTR').innerText = avg(metrics.mttr);
  r('mAUC').innerText = metrics.tp > 0 ? '0.98' : '—';
  r('mFPR').innerText = metrics.ev > 0 ? (metrics.fp / metrics.ev * 100).toFixed(2) + '%' : '0%';
}

function processEv(e) {
  metrics.ev++; e.ts = new Date().toISOString().split('T')[1].substr(0,8);
  // Simple heuristic instead of real iForest
  let score = 0.1 + Math.random()*0.1;
  if (e.sc === 'sys_execve' && e.tgt.includes('sh')) score += 0.65;
  if (e.sc === 'sys_connect' && e.port === 445) score += 0.70;
  if (e.sc === 'sys_rename' && e.tgt.includes('locked')) score += 0.80;
  e.score = Math.min(1.0, score);
  e.al = e.score > 0.72;

  state.hist.push(e); if(state.hist.length > 50) state.hist.shift();

  // DOM Stream
  const er = document.createElement('div'); er.className = `er ${e.al ? 'al' : ''}`;
  const c = e.score > 0.72 ? 'c-hi' : (e.score > 0.4 ? 'c-md' : 'c-lo');
  er.innerHTML = `<span class="et">${e.ts}</span><span class="ep">${e.pod}</span><span class="es">${e.sc}</span><span class="eta">${e.tgt}</span><span class="esc ${c}">${e.score.toFixed(2)}</span>`;
  const st = r('stream'); st.prepend(er);
  if (st.children.length > 50) st.removeChild(st.lastChild);

  if (e.al) handleAlert(e);
}

function handleAlert(e) {
  metrics.al++;
  if (state.attack) {
    metrics.tp++;
    if (metrics.start) {
      metrics.mttd.push((Date.now() - metrics.start) / 1000);
      metrics.start = null;
    }
  } else metrics.fp++;

  // ExIFFI & Diagnosis
  let ex = 'Payload size (40%)';
  let cause = 'unknown', conf = 0.4;
  if (e.tgt.includes('sh')) { ex = 'Binary sh (85%)'; cause = 'compromise'; conf = 0.92; }
  else if (e.port === 445) { ex = 'Port 445 (78%)'; cause = 'compromise'; conf = 0.88; }
  else if (e.tgt.includes('locked')) { ex = 'Extension .locked (95%)'; cause = 'compromise'; conf = 0.98; }

  const al = document.createElement('div'); al.className = 'item';
  al.innerHTML = `<div class="ih"><span>🚨 ${e.pod}</span><span class="is">${e.score.toFixed(3)}</span></div>
  <div class="ix">ExIFFI: ${ex}</div><div class="idg">Diag: <b>${cause}</b> (${(conf*100).toFixed(0)}%)</div>`;
  const list = r('alertList'); if(list.querySelector('.empty')) list.innerHTML = '';
  list.prepend(al);

  setTimeout(() => handleAction(e.pod, cause, conf), 500);
}

function handleAction(pod, cause, conf) {
  const isC = svcs[pod] && svcs[pod].crit;
  const act = cause === 'compromise' ? (isC ? 'FailoverQuarantine' : 'Redeploy') : 'QuarantineOnly';
  
  const id = `act-${pod}-${Date.now()}`;
  const d = document.createElement('div'); d.className = 'item act'; d.id = id;
  d.innerHTML = `<div class="ih"><span><span class="at">${act}</span> → ${pod}</span><span class="ast executing" id="st-${id}">EXECUTING</span></div>
  <div class="ix">Cause: ${cause} (${(conf*100).toFixed(0)}%)</div>`;
  const list = r('actionList'); if(list.querySelector('.empty')) list.innerHTML = '';
  list.prepend(d);

  if(svcs[pod]) { svcs[pod].status = 'quarantined'; renderSvcs(); }

  setTimeout(() => {
    r(`st-${id}`).className = 'ast completed'; r(`st-${id}`).innerText = 'COMPLETED';
    metrics.mttr.push(3.0 + Math.random()*2);
    if(svcs[pod] && act !== 'QuarantineOnly') {
      svcs[pod].status = 'redeploying'; renderSvcs();
      setTimeout(() => { svcs[pod].status = 'healthy'; renderSvcs(); }, 2000);
    }
  }, 3000);
}

function launchAttack() {
  if (state.attack) return;
  state.attack = true; state.stage = 0; state.ctr = 0; metrics.start = Date.now();
  r('banner').classList.remove('hidden'); updateStage();
}

function updateStage() {
  if(state.stage < 0 || state.stage > 3) return;
  r('stageName').innerText = ATK[state.stage].n;
  document.querySelectorAll('.sd').forEach(d => {
    let s = parseInt(d.dataset.s);
    d.className = 'sd ' + (s === state.stage ? 'active' : (s < state.stage ? 'done' : ''));
  });
}

function resetAll() {
  state.attack = false; state.stage = -1; r('banner').classList.add('hidden');
  Object.values(svcs).forEach(v => v.status = 'healthy'); renderSvcs();
  metrics = { ev: 0, al: 0, mttd: [], mttr: [], fp: 0, tp: 0, start: null };
  r('stream').innerHTML = ''; r('alertList').innerHTML = '<div class="empty">Monitoring… no alerts yet</div>';
  r('actionList').innerHTML = '<div class="empty">No actions taken yet</div>';
}

function loop() {
  if (!state.running) return;
  const pods = Object.keys(svcs);
  
  if (state.attack) {
    if (state.ctr < 20) {
      let st = Math.floor(state.ctr / 5);
      if (st !== state.stage && st < 4) { state.stage = st; updateStage(); }
      let a = ATK[Math.min(st, 3)];
      processEv({ pod: 'ehr', sc: a.sc, tgt: a.tgt, port: a.port });
      state.ctr++;
    } else {
      state.attack = false; state.stage = -1; r('banner').classList.add('hidden');
    }
  } else {
    // Benign
    const sc = ['sys_read','sys_write','sys_connect','sys_close'][Math.floor(Math.random()*4)];
    const pod = pods[Math.floor(Math.random()*pods.length)];
    svcs[pod].reqs++;
    processEv({ pod, sc, tgt: `/var/data/${Math.floor(Math.random()*100)}.log`, port: sc==='sys_connect'?443:0 });
  }

  if (metrics.ev % 5 === 0) renderSvcs();
  updateMetrics();
  
  setTimeout(loop, state.attack ? 400 : 800 + Math.random()*500);
}

renderSvcs();
setTimeout(loop, 1000);
