// SentinelCloud-Advanced Dashboard – Enhanced Frontend Logic
const socket = io();
const MAX_EVENTS = 80;

const btnAttack = document.getElementById('btn-attack') || document.getElementById('btnAttack');
const btnReset = document.getElementById('btn-reset');

// Toast Notification Helper
function showToast(message, isError = false) {
  let toast = document.getElementById('toast-notification');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toast-notification';
    toast.style.cssText = `
      position: fixed; bottom: 24px; right: 24px; z-index: 9999;
      padding: 12px 20px; border-radius: 8px; font-size: 13px; font-weight: 600;
      color: #fff; box-shadow: 0 4px 20px rgba(0,0,0,0.4); transition: all 0.3s ease;
      display: flex; align-items: center; gap: 8px; font-family: 'Inter', sans-serif;
    `;
    document.body.appendChild(toast);
  }
  toast.style.background = isError ? 'linear-gradient(135deg, #ef4444, #dc2626)' : 'linear-gradient(135deg, #10b981, #059669)';
  toast.innerHTML = isError ? `⚠️ ${message}` : `✓ ${message}`;
  toast.style.opacity = '1';
  toast.style.transform = 'translateY(0)';
  
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
  }, 3500);
}

// ── Render Medical Services ──
function renderServices(data) {
  const grid = document.getElementById('services-grid') || document.getElementById('svcGrid');
  if (!grid) return;
  grid.innerHTML = '';
  for (const [name, svc] of Object.entries(data)) {
    const card = document.createElement('div');
    card.className = `svc-card ${svc.status}`;
    card.id = `svc-${name}`;
    card.innerHTML = `
      <div class="svc-name">${name}</div>
      <span class="svc-badge ${svc.status}">${svc.status}</span>
      ${svc.critical ? '<div class="svc-critical">⚠ Critical Service</div>' : ''}
      <div class="svc-meta">Port ${svc.port} · ${svc.requests || 0} reqs</div>
    `;
    grid.appendChild(card);
  }
}

// Initial Fetch
fetch('/api/services')
  .then(r => r.json())
  .then(renderServices)
  .catch(err => console.error('Error fetching services:', err));

// ── Real-Time Socket Listeners ──

// Service Update
socket.on('service_update', (data) => {
  const card = document.getElementById(`svc-${data.name}`);
  if (card) {
    card.className = `svc-card ${data.status}`;
    const badge = card.querySelector('.svc-badge');
    if (badge) {
      badge.className = `svc-badge ${data.status}`;
      badge.textContent = data.status;
    }
  }
  fetch('/api/services').then(r => r.json()).then(renderServices).catch(() => {});
});

// Syscall Events
const eventStream = document.getElementById('event-stream') || document.getElementById('stream');

function getScoreClass(score) {
  if (score >= 0.72) return 'score-high';
  if (score >= 0.4) return 'score-med';
  return 'score-low';
}

socket.on('event', (ev) => {
  if (!eventStream) return;
  const row = document.createElement('div');
  row.className = `event-row ${ev.is_alert ? 'alert-row' : ''}`;
  const time = ev.timestamp ? (ev.timestamp.includes('T') ? ev.timestamp.split('T')[1].substring(0, 8) : ev.timestamp) : '';
  const scoreVal = typeof ev.anomaly_score === 'number' ? ev.anomaly_score.toFixed(2) : '0.00';
  
  row.innerHTML = `
    <span class="event-time">${time}</span>
    <span class="event-pod">${ev.pod_name || ev.pod || ''}</span>
    <span class="event-syscall">${ev.syscall || ''}</span>
    <span class="event-target">${ev.target || ''}</span>
    <span class="event-score ${getScoreClass(ev.anomaly_score)}">${scoreVal}</span>
  `;
  eventStream.prepend(row);
  while (eventStream.children.length > MAX_EVENTS) {
    eventStream.removeChild(eventStream.lastChild);
  }
});

// Security Alerts
const alertList = document.getElementById('alert-list') || document.getElementById('alertList');
let hasAlerts = false;

socket.on('alert', (alert) => {
  if (!alertList) return;
  if (!hasAlerts) { alertList.innerHTML = ''; hasAlerts = true; }
  const item = document.createElement('div');
  item.className = 'alert-item';
  const diag = alert.diagnosis || {};
  const scoreVal = typeof alert.anomaly_score === 'number' ? alert.anomaly_score.toFixed(3) : '0.000';
  const confVal = typeof diag.confidence === 'number' ? (diag.confidence * 100).toFixed(0) : '0';
  
  item.innerHTML = `
    <div class="alert-header">
      <span class="alert-pod">🚨 ${alert.pod_name || alert.pod}</span>
      <span class="alert-score">${scoreVal}</span>
    </div>
    <div class="alert-explanation">ExIFFI: ${alert.explanation || 'N/A'}</div>
    <div class="alert-diagnosis">
      Diagnosis: <strong>${diag.root_cause || '?'}</strong> (${confVal}% confidence)
      ${diag.evidence && diag.evidence.length ? ' · ' + diag.evidence.slice(0, 2).join(', ') : ''}
    </div>
    <div style="font-size:10px;color:#64748b;margin-top:3px">Source: ${alert.source || 'iforest'}</div>
  `;
  alertList.prepend(item);
});

// MAPE-K Actions
const actionList = document.getElementById('action-list') || document.getElementById('actionList');
let hasActions = false;

socket.on('action', (act) => {
  if (!actionList) return;
  if (!hasActions) { actionList.innerHTML = ''; hasActions = true; }
  
  let existing = document.getElementById(`action-${act.pod}-${act.action}`);
  if (existing) {
    const badge = existing.querySelector('.action-status-badge');
    if (badge) {
      badge.className = `action-status-badge ${act.status}`;
      badge.textContent = act.status;
    }
    return;
  }
  
  const item = document.createElement('div');
  item.className = 'action-item';
  item.id = `action-${act.pod}-${act.action}`;
  const confVal = typeof act.confidence === 'number' ? (act.confidence * 100).toFixed(0) : '0';
  
  item.innerHTML = `
    <div class="action-header">
      <span><span class="action-type">${act.action}</span> → ${act.pod}</span>
      <span class="action-status-badge ${act.status}">${act.status}</span>
    </div>
    <div class="action-details">
      Root cause: ${act.root_cause} (${confVal}%)
      ${act.evidence && act.evidence.length ? '<br>' + act.evidence.slice(0, 2).join(', ') : ''}
    </div>
  `;
  actionList.prepend(item);
});

// Metrics Bar Update
socket.on('metrics_update', (m) => {
  const mEv = document.getElementById('m-events') || document.getElementById('mEv');
  const mAl = document.getElementById('m-alerts') || document.getElementById('mAl');
  const mMttd = document.getElementById('m-mttd') || document.getElementById('mMTTD');
  const mMttr = document.getElementById('m-mttr') || document.getElementById('mMTTR');
  const mAuc = document.getElementById('m-auc') || document.getElementById('mAUC');
  const mFpr = document.getElementById('m-fpr') || document.getElementById('mFPR');

  if (mEv) mEv.textContent = m.events_processed.toLocaleString();
  if (mAl) mAl.textContent = m.alerts_total;
  if (mMttd) mMttd.textContent = m.mttd_avg > 0 ? m.mttd_avg + 's' : '—';
  if (mMttr) mMttr.textContent = m.mttr_avg > 0 ? m.mttr_avg + 's' : '—';
  if (mAuc) mAuc.textContent = m.auc_estimate > 0 ? m.auc_estimate : '—';
  if (mFpr) mFpr.textContent = (typeof m.fpr === 'number' ? m.fpr.toFixed(2) : m.fpr) + '%';
});

// Attack Stage Management
socket.on('attack_stage', (data) => {
  const banner = document.getElementById('attack-banner') || document.getElementById('banner');
  const stageName = document.getElementById('attack-stage-name') || document.getElementById('stageName');
  
  if (!banner) return;

  if (data.stage === -1) {
    banner.classList.add('hidden');
    if (btnAttack) {
      btnAttack.disabled = false;
      btnAttack.innerHTML = '⚡ Launch Attack';
      btnAttack.style.opacity = '1';
    }
    return;
  }

  banner.classList.remove('hidden');
  if (stageName) stageName.textContent = data.name;

  if (btnAttack) {
    btnAttack.disabled = true;
    btnAttack.innerHTML = `🔥 Stage ${data.stage + 1}: ${data.name}`;
    btnAttack.style.opacity = '0.7';
  }

  document.querySelectorAll('.stage-dot, .sd').forEach(dot => {
    const s = parseInt(dot.dataset.stage || dot.dataset.s);
    dot.classList.remove('active', 'done');
    if (s === data.stage) dot.classList.add('active');
    else if (s < data.stage) dot.classList.add('done');
  });
});

// Reset Handler
socket.on('reset', () => {
  if (eventStream) eventStream.innerHTML = '';
  if (alertList) alertList.innerHTML = '<div class="empty-state">No alerts yet</div>';
  if (actionList) actionList.innerHTML = '<div class="empty-state">No actions yet</div>';
  hasAlerts = false;
  hasActions = false;

  const banner = document.getElementById('attack-banner') || document.getElementById('banner');
  if (banner) banner.classList.add('hidden');

  if (btnAttack) {
    btnAttack.disabled = false;
    btnAttack.innerHTML = '⚡ Launch Attack';
    btnAttack.style.opacity = '1';
  }

  if (btnReset) {
    btnReset.disabled = false;
    btnReset.innerHTML = '↻ Reset';
    btnReset.style.opacity = '1';
  }

  // Clear metrics immediately
  const mEv = document.getElementById('m-events') || document.getElementById('mEv');
  const mAl = document.getElementById('m-alerts') || document.getElementById('mAl');
  const mMttd = document.getElementById('m-mttd') || document.getElementById('mMTTD');
  const mMttr = document.getElementById('m-mttr') || document.getElementById('mMTTR');
  const mAuc = document.getElementById('m-auc') || document.getElementById('mAUC');
  const mFpr = document.getElementById('m-fpr') || document.getElementById('mFPR');

  if (mEv) mEv.textContent = '0';
  if (mAl) mAl.textContent = '0';
  if (mMttd) mMttd.textContent = '—';
  if (mMttr) mMttr.textContent = '—';
  if (mAuc) mAuc.textContent = '—';
  if (mFpr) mFpr.textContent = '0%';

  fetch('/api/services').then(r => r.json()).then(renderServices).catch(() => {});
  showToast('Dashboard and metrics reset successfully!');
});

// ── Button Click Listeners ──

if (btnAttack) {
  btnAttack.addEventListener('click', () => {
    btnAttack.disabled = true;
    btnAttack.innerHTML = '⏳ Launching Attack...';
    btnAttack.style.opacity = '0.7';

    fetch('/api/attack', { method: 'POST' })
      .then(async res => {
        const data = await res.json();
        if (!res.ok || data.error) {
          showToast(data.error || 'Failed to launch attack', true);
          btnAttack.disabled = false;
          btnAttack.innerHTML = '⚡ Launch Attack';
          btnAttack.style.opacity = '1';
        } else {
          showToast('Ransomware attack simulation initialized!');
        }
      })
      .catch(err => {
        showToast('Network error triggering attack', true);
        btnAttack.disabled = false;
        btnAttack.innerHTML = '⚡ Launch Attack';
        btnAttack.style.opacity = '1';
      });
  });
}

if (btnReset) {
  btnReset.addEventListener('click', () => {
    btnReset.disabled = true;
    btnReset.innerHTML = '↻ Resetting...';
    btnReset.style.opacity = '0.7';

    fetch('/api/reset', { method: 'POST' })
      .then(res => res.json())
      .catch(err => {
        showToast('Error resetting simulation state', true);
        btnReset.disabled = false;
        btnReset.innerHTML = '↻ Reset';
        btnReset.style.opacity = '1';
      });
  });
}

// Global functions for inline onclick fallbacks
window.launchAttack = function() {
  if (btnAttack) btnAttack.click();
};

window.resetAll = function() {
  if (btnReset) btnReset.click();
};
