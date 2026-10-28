/**
 * Cloud XDR URL Threat Analyzer - Client Application Controller
 * Fully connects Dashboard, Scanner, History, Comparison, Bulk, Watchlists,
 * Rules, Feedback, AI Chat, API Tokens, and Admin Management.
 */

const ORDER = ['queued', 'detonating', 'analyzing', 'scoring', 'done'];
const COLORS = {
  critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', info: 'var(--info)',
  Low: '#4dd4ac', Medium: 'var(--medium)', High: 'var(--high)', Critical: 'var(--critical)',
  Good: '#4dd4ac', Fair: 'var(--medium)', Poor: 'var(--high)'
};

const $ = (id) => document.getElementById(id);

// Safe DOM Builder (No innerHTML on untrusted data)
function el(tag, cls, text, kids) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  (kids || []).forEach(k => {
    if (k) n.appendChild(k);
  });
  return n;
}

// App State
const state = {
  currentUser: null,
  csrfToken: null,
  activeView: 'scanner',
  currentScanId: null,
  compareBaseId: null,
  historyOffset: 0,
  historyLimit: 15,
};

// ============================================================================
// API Client with CSRF handling
// ============================================================================
async function api(url, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  if (state.csrfToken && ['POST', 'PUT', 'PATCH', 'DELETE'].includes((opts.method || 'GET').toUpperCase())) {
    headers['X-CSRF-Token'] = state.csrfToken;
  }
  opts.headers = headers;
  opts.credentials = 'same-origin';

  const res = await fetch(url, opts);
  const newCsrf = res.headers.get('X-CSRF-Token');
  if (newCsrf) state.csrfToken = newCsrf;

  if (res.status === 401 && !url.includes('/auth/login') && !url.includes('/auth/me')) {
    state.currentUser = null;
    renderUserBar();
    showLoginModal();
    throw new Error('Please log in to continue.');
  }

  const contentType = res.headers.get('content-type') || '';
  if (!res.ok) {
    let errMsg = 'Request failed';
    try {
      const errJson = await res.json();
      errMsg = errJson.detail || errJson.error || errMsg;
    } catch (_) {}
    throw new Error(errMsg);
  }

  if (contentType.includes('application/json')) {
    return await res.json();
  }
  return res;
}

// ============================================================================
// Initialization & Auth
// ============================================================================
async function initApp() {
  setupNavigation();
  setupEventListeners();

  try {
    const user = await api('/api/v1/auth/me');
    state.currentUser = user;
    const csrfRes = await api('/api/v1/auth/csrf');
    state.csrfToken = csrfRes.csrf_token;
  } catch (_) {
    state.currentUser = null;
  }

  renderUserBar();
  showView('scanner');
}

function setupNavigation() {
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.onclick = () => {
      const view = btn.dataset.view;
      showView(view);
    };
  });
}

function showView(viewName) {
  state.activeView = viewName;
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.view === viewName));
  document.querySelectorAll('.view-container').forEach(c => c.classList.toggle('active', c.id === `view-${viewName}`));

  if (viewName === 'dashboard') loadDashboard();
  if (viewName === 'history') loadHistory();
  if (viewName === 'bulk') loadBulkJobs();
  if (viewName === 'watchlists') loadWatchlists();
  if (viewName === 'rules') loadRules();
  if (viewName === 'tokens') loadTokens();
  if (viewName === 'admin') loadAdminView();
}

function renderUserBar() {
  const bar = $('user-bar');
  bar.replaceChildren();

  if (state.currentUser) {
    const pill = el('div', 'user-pill', null, [
      el('span', null, state.currentUser.email),
      el('span', `role-badge role-${state.currentUser.role}`, state.currentUser.role)
    ]);
    const logoutBtn = el('button', 'btn-sm', 'Logout');
    logoutBtn.onclick = async () => {
      try {
        await api('/api/v1/auth/logout', { method: 'POST' });
      } catch (_) {}
      state.currentUser = null;
      renderUserBar();
      showView('scanner');
    };
    bar.appendChild(pill);
    bar.appendChild(logoutBtn);
  } else {
    const loginBtn = el('button', 'btn-sm btn-accent', 'Log In');
    loginBtn.onclick = () => showLoginModal();
    bar.appendChild(loginBtn);
  }
}

// ============================================================================
// Scanner View (Preserving exact logic and UI)
// ============================================================================
function setupEventListeners() {
  document.querySelectorAll('.chip').forEach(c => c.onclick = () => { $('url').value = c.dataset.url; });

  $('form').onsubmit = async (e) => {
    e.preventDefault();
    $('err').classList.add('hidden');
    $('out').replaceChildren();
    const url = $('url').value.trim();
    if (!url) return;
    $('go').disabled = true;

    try {
      const res = await api('/api/v1/scans', {
        method: 'POST',
        body: { url, allow_private: url.includes('localhost') || url.includes('127.0.0.1') }
      });
      state.currentScanId = res.id;
      pollScan(res.id);
    } catch (ex) {
      showErr(ex.message);
      $('go').disabled = false;
    }
  };
}

function showErr(m) {
  $('err').textContent = m;
  $('err').classList.remove('hidden');
}

function setStep(status) {
  $('steps').classList.remove('hidden');
  const idx = ORDER.indexOf(status);
  document.querySelectorAll('.step').forEach(s => {
    const i = ORDER.indexOf(s.dataset.s);
    s.classList.toggle('done', i < idx || status === 'done');
    s.classList.toggle('active', i === idx && status !== 'done');
  });
}

async function pollScan(id) {
  try {
    const job = await api(`/api/jobs/${id}`);
    if (job.status === 'error') {
      showErr('Analysis failed: ' + (job.error || 'Unknown error'));
      $('go').disabled = false;
      return;
    }
    setStep(job.status);
    if (job.status !== 'done') {
      setTimeout(() => pollScan(id), 600);
      return;
    }
    renderScanReport(job, id);
    $('go').disabled = false;
  } catch (err) {
    showErr(err.message);
    $('go').disabled = false;
  }
}

function section(title, kids) {
  return el('div', 'card', null, [el('h2', null, title), ...kids]);
}

function renderScanReport(job, id) {
  state.currentScanId = id;
  const r = job.report;
  const ev = r.evidence || {};
  const out = $('out');
  out.replaceChildren();

  // Top action bar (Exports, Rescan, Chat toggle)
  const actionRow = el('div', 'filter-row', null, [
    Object.assign(el('button', 'btn-sm', 'Export JSON'), {
      onclick: () => window.open(`/api/v1/scans/${id}/export/json`, '_blank')
    }),
    Object.assign(el('button', 'btn-sm', 'Export PDF'), {
      onclick: () => window.open(`/api/v1/scans/${id}/export/pdf`, '_blank')
    }),
    Object.assign(el('button', 'btn-sm', 'Re-scan Target'), {
      onclick: async () => {
        try {
          const res = await api(`/api/v1/scans/${id}/rescan`, { method: 'POST' });
          pollScan(res.id);
        } catch (ex) { alert(ex.message); }
      }
    }),
    Object.assign(el('button', 'btn-sm btn-accent', 'AI Analyst Assistant'), {
      onclick: () => toggleChatPanel(id)
    }),
  ]);
  out.appendChild(actionRow);

  // Verdict Gauge
  const gauge = el('div', 'gauge', null, [
    el('div', 'score', String(r.threat_score)),
    el('div', 'lvl', r.threat_level.toUpperCase()),
    el('div', 'mini', `Threat score  •  Hygiene ${r.hygiene_score}/100 (${r.hygiene_level})`)
  ]);
  gauge.querySelector('.score').style.color = COLORS[r.threat_level];
  gauge.querySelector('.lvl').style.background = COLORS[r.threat_level];

  const right = el('div', null, null, [
    el('div', 'summary', r.summary),
    el('div', 'mini', `Landed on: ${r.final_url || r.url}   •   ${(ev.requests || []).length} requests, ` +
      `${(ev.scripts || []).length + (ev.inline_script_count || 0)} scripts, ${(ev.downloads || []).length} downloads, ${ev.elapsed_s || 0}s`)
  ]);

  if (r.has_screenshot) {
    const im = el('img', 'shot');
    im.src = `/api/v1/scans/${id}/screenshot.png`;
    im.alt = 'Page screenshot';
    right.appendChild(im);
  }
  out.appendChild(el('div', 'card top', null, [gauge, right]));

  // Analyst Feedback Section
  renderFeedbackBar(out, id);

  // Chat Panel Container (Collapsible)
  const chatContainer = el('div', 'hidden', null);
  chatContainer.id = 'scan-chat-container';
  out.appendChild(chatContainer);

  // Findings Section
  const fl = (r.findings || []).map(f => {
    const head = el('div', null, null, [
      Object.assign(el('span', 'sev', f.severity), {}),
      el('b', null, f.title),
      el('span', 'tag', `${f.group} • conf ${Number(f.confidence).toFixed(2)}`)
    ]);
    head.firstChild.style.background = COLORS[f.severity];
    const box = el('div', 'f', null, [head]);
    if (f.detail) box.appendChild(el('div', 'detail', f.detail));
    (f.evidence || []).forEach(x => box.appendChild(el('div', 'ev', x)));
    return box;
  });
  out.appendChild(section(`Findings (${(r.findings || []).length})`, fl.length ? fl : [el('div', 'mini', 'No findings recorded.')]));

  // Redirect chain
  if ((ev.redirect_chain || []).length > 1) {
    const t = el('table', null, null, [
      el('tr', null, null, [el('th', null, '#'), el('th', null, 'Status'), el('th', null, 'URL')]),
      ...ev.redirect_chain.map((c, i) => el('tr', null, null, [
        el('td', null, String(i + 1)),
        el('td', null, String(c.status)),
        el('td', 'mono', c.url)
      ]))
    ]);
    out.appendChild(section('Redirect chain', [t]));
  }

  // Downloads
  if ((ev.downloads || []).length) {
    const t = el('table', null, null, [
      el('tr', null, null, [el('th', null, 'File'), el('th', null, 'Size'), el('th', null, 'Detected as'), el('th', null, 'SHA-256')]),
      ...ev.downloads.map(d => el('tr', null, null, [
        el('td', null, d.filename),
        el('td', null, `${d.size} B`),
        el('td', null, d.magic),
        el('td', 'mono', d.sha256)
      ]))
    ]);
    out.appendChild(section('Downloads (hashed then deleted, never executed)', [t]));
  }

  // Contacted Hosts
  if ((ev.requests || []).length) {
    const counts = {};
    ev.requests.forEach(q => { counts[q.host] = (counts[q.host] || 0) + 1; });
    const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([h, n]) =>
      el('tr', null, null, [el('td', 'mono', h), el('td', null, String(n))])
    );
    out.appendChild(section('Hosts contacted', [
      el('table', null, null, [el('tr', null, null, [el('th', null, 'Host'), el('th', null, 'Requests')]), ...rows])
    ]));
  }

  // LLM Payload Preview
  out.appendChild(section('Structured AI Payload (Prompt Injection Safe)', [
    el('pre', 'ev', JSON.stringify(r.llm_payload, null, 2))
  ]));
}

function renderFeedbackBar(container, scanId) {
  const bar = el('div', 'feedback-bar', null, [
    el('span', null, 'Analyst Feedback:'),
    Object.assign(el('button', 'fb-btn tp', 'True Positive'), {
      onclick: () => submitFeedback(scanId, 'true_positive')
    }),
    Object.assign(el('button', 'fb-btn fp', 'False Positive'), {
      onclick: () => submitFeedback(scanId, 'false_positive')
    }),
    Object.assign(el('button', 'fb-btn nr', 'Needs Review'), {
      onclick: () => submitFeedback(scanId, 'needs_review')
    }),
    el('span', 'mini', '• Annotations logged with provenance.')
  ]);
  container.appendChild(bar);
}

async function submitFeedback(scanId, verdict) {
  if (!state.currentUser) {
    alert('Please log in as an Analyst or Admin to submit feedback.');
    showLoginModal();
    return;
  }
  const notes = prompt(`Optional analyst notes for [${verdict.replace('_', ' ').toUpperCase()}]:`);
  try {
    await api(`/api/v1/scans/${scanId}/feedback`, {
      method: 'POST',
      body: { verdict, notes: notes || '' }
    });
    alert(`Feedback saved as ${verdict.toUpperCase()}`);
  } catch (ex) {
    alert(ex.message);
  }
}

// ============================================================================
// AI Assistant Chat Panel
// ============================================================================
async function toggleChatPanel(scanId) {
  const container = $('scan-chat-container');
  if (!container) return;
  if (!container.classList.contains('hidden')) {
    container.classList.add('hidden');
    return;
  }
  container.classList.remove('hidden');
  container.replaceChildren();

  const chatBox = el('div', 'chat-drawer', null);
  const header = el('div', 'chat-header', null, [
    el('b', null, 'AI Threat Analyst Assistant'),
    el('span', 'mini', 'Grounded in recorded sandbox evidence')
  ]);
  const msgArea = el('div', 'chat-msgs');
  msgArea.id = 'chat-messages-area';

  const inputBar = el('div', 'chat-input-bar', null);
  const input = el('input', 'filter-input', null);
  input.type = 'text';
  input.placeholder = 'Ask a question about this scan (e.g. "Is this malicious?", "Explain downloads")...';
  input.style.flex = '1';

  const sendBtn = el('button', 'btn-sm btn-accent', 'Send');
  sendBtn.onclick = async () => {
    const text = input.value.trim();
    if (!text) return;
    input.value = '';
    msgArea.appendChild(el('div', 'chat-bubble user', text));
    msgArea.scrollTop = msgArea.scrollHeight;

    try {
      const reply = await api(`/api/v1/scans/${scanId}/chat`, {
        method: 'POST',
        body: { message: text }
      });
      msgArea.appendChild(el('div', 'chat-bubble assistant', reply.content));
      msgArea.scrollTop = msgArea.scrollHeight;
    } catch (e) {
      msgArea.appendChild(el('div', 'chat-bubble assistant', `Error: ${e.message}`));
    }
  };

  input.onkeydown = (e) => { if (e.key === 'Enter') sendBtn.click(); };

  inputBar.appendChild(input);
  inputBar.appendChild(sendBtn);

  chatBox.appendChild(header);
  chatBox.appendChild(msgArea);
  chatBox.appendChild(inputBar);
  container.appendChild(chatBox);

  // Load history
  try {
    const history = await api(`/api/v1/scans/${scanId}/chat`);
    if (history.length) {
      history.forEach(m => msgArea.appendChild(el('div', `chat-bubble ${m.role}`, m.content)));
    } else {
      msgArea.appendChild(el('div', 'chat-bubble assistant',
        'Hello! I am your AI Threat Analyst Assistant. Ask me anything about this scan\'s findings, scripts, contacted domains, or recommended mitigations.'
      ));
    }
    msgArea.scrollTop = msgArea.scrollHeight;
  } catch (_) {}
}

// ============================================================================
// Dashboard View
// ============================================================================
async function loadDashboard() {
  const container = $('view-dashboard');
  container.replaceChildren(el('div', 'empty-state', 'Loading real telemetry from database...'));

  try {
    const stats = await api('/api/v1/dashboard/stats');
    container.replaceChildren();

    // Metric Tiles
    const tiles = el('div', 'metrics-grid', null, [
      metricTile('Total Scans', stats.total_scans, `${stats.scans_today} today / ${stats.scans_this_week} this week`),
      metricTile('Threat Levels', `${stats.risk_distribution.Critical || 0} Crit`, `${stats.risk_distribution.High || 0} High, ${stats.risk_distribution.Medium || 0} Med`),
      metricTile('Blocked Targets', stats.blocked_count, `${stats.allowlist_count} allowlisted`),
      metricTile('Active Watchlists', stats.active_watchlists, `Worker: ${stats.worker_status.toUpperCase()}`)
    ]);
    container.appendChild(tiles);

    // Threat Distribution Bar
    const totalRisk = (stats.risk_distribution.Low || 0) + (stats.risk_distribution.Medium || 0) +
                      (stats.risk_distribution.High || 0) + (stats.risk_distribution.Critical || 0) || 1;
    const bar = el('div', 'card', null, [
      el('h2', null, 'Threat Score Distribution'),
      el('div', 'dist-bar', null, [
        distSeg(stats.risk_distribution.Low || 0, totalRisk, '#4dd4ac', 'Low'),
        distSeg(stats.risk_distribution.Medium || 0, totalRisk, 'var(--medium)', 'Medium'),
        distSeg(stats.risk_distribution.High || 0, totalRisk, 'var(--high)', 'High'),
        distSeg(stats.risk_distribution.Critical || 0, totalRisk, 'var(--critical)', 'Critical'),
      ]),
      el('div', 'mini', `Low: ${stats.risk_distribution.Low || 0} • Medium: ${stats.risk_distribution.Medium || 0} • High: ${stats.risk_distribution.High || 0} • Critical: ${stats.risk_distribution.Critical || 0}`)
    ]);
    container.appendChild(bar);

    // Top Suspicious Domains Table
    const domRows = stats.top_suspicious_domains.map(d => el('tr', null, null, [
      el('td', 'mono', d.domain),
      el('td', null, String(d.count)),
      el('td', null, `${d.max_threat_score}/100`)
    ]));
    const domTable = el('div', 'card', null, [
      el('h2', null, 'Top Malicious / Suspicious Domains Observed'),
      domRows.length ? el('table', 'data-table', null, [
        el('tr', null, null, [el('th', null, 'Domain'), el('th', null, 'Scans'), el('th', null, 'Peak Threat Score')]),
        ...domRows
      ]) : el('div', 'empty-state', 'No suspicious domains recorded yet.')
    ]);
    container.appendChild(domTable);

    // Recent Scans Table
    const recentRows = stats.recent_scans.map(s => el('tr', null, null, [
      el('td', 'mono', s.url.length > 50 ? s.url.slice(0, 50) + '...' : s.url),
      el('td', 'mono', s.normalized_domain),
      el('td', null, null, [
        Object.assign(el('span', 'sev', s.threat_level), { style: `background:${COLORS[s.threat_level]}` })
      ]),
      el('td', null, `${s.threat_score}/100`),
      el('td', null, null, [
        Object.assign(el('button', 'btn-sm', 'View'), {
          onclick: () => {
            showView('scanner');
            pollScan(s.id);
          }
        })
      ])
    ]));
    const recTable = el('div', 'card', null, [
      el('h2', null, 'Recent Detonations'),
      recentRows.length ? el('table', 'data-table', null, [
        el('tr', null, null, [el('th', null, 'URL'), el('th', null, 'Domain'), el('th', null, 'Verdict'), el('th', null, 'Score'), el('th', null, 'Action')]),
        ...recentRows
      ]) : el('div', 'empty-state', 'No scans recorded yet.')
    ]);
    container.appendChild(recTable);

  } catch (err) {
    container.replaceChildren(el('div', 'err', `Failed to load dashboard: ${err.message}`));
  }
}

function metricTile(title, val, sub) {
  return el('div', 'metric-card', null, [
    el('div', 'metric-title', title),
    el('div', 'metric-val', String(val)),
    el('div', 'metric-sub', sub)
  ]);
}

function distSeg(count, total, color, label) {
  const pct = ((count / total) * 100).toFixed(1);
  const s = el('div', 'dist-seg');
  s.style.width = `${pct}%`;
  s.style.background = color;
  s.title = `${label}: ${count} (${pct}%)`;
  return s;
}

// ============================================================================
// History View with Search, Filters, and Pagination
// ============================================================================
async function loadHistory() {
  const container = $('view-history');
  container.replaceChildren();

  // Search & Filter Bar
  const filterRow = el('div', 'filter-row', null);
  const searchInput = el('input', 'filter-input');
  searchInput.placeholder = 'Search URL or domain...';
  searchInput.style.flex = '1';

  const levelSelect = el('select', 'filter-input', null, [
    el('option', null, 'All Threat Levels'),
    el('option', null, 'Critical'),
    el('option', null, 'High'),
    el('option', null, 'Medium'),
    el('option', null, 'Low'),
  ]);

  const searchBtn = el('button', 'btn-sm btn-accent', 'Filter');
  searchBtn.onclick = () => fetchAndRenderHistory(searchInput.value, levelSelect.value);

  filterRow.appendChild(searchInput);
  filterRow.appendChild(levelSelect);
  filterRow.appendChild(searchBtn);
  container.appendChild(filterRow);

  const tableContainer = el('div', 'table-wrap');
  tableContainer.id = 'history-table-container';
  container.appendChild(tableContainer);

  await fetchAndRenderHistory('', 'All Threat Levels');
}

async function fetchAndRenderHistory(query, level) {
  const container = $('history-table-container');
  if (!container) return;
  container.replaceChildren(el('div', 'empty-state', 'Loading scan history...'));

  let url = `/api/v1/scans?limit=${state.historyLimit}&offset=${state.historyOffset}`;
  if (query) url += `&q=${encodeURIComponent(query)}`;
  if (level && level !== 'All Threat Levels') url += `&threat_level=${level}`;

  try {
    const scans = await api(url);
    if (!scans.length) {
      container.replaceChildren(el('div', 'empty-state', 'No scans match your search criteria.'));
      return;
    }

    const rows = scans.map(s => el('tr', null, null, [
      el('td', 'mono', s.url.length > 55 ? s.url.slice(0, 55) + '...' : s.url),
      el('td', 'mono', s.normalized_domain),
      el('td', null, null, [
        Object.assign(el('span', 'sev', s.threat_level), { style: `background:${COLORS[s.threat_level]}` })
      ]),
      el('td', null, `${s.threat_score}/100`),
      el('td', 'mini', new Date(s.created_at).toLocaleString()),
      el('td', null, null, [
        Object.assign(el('button', 'btn-sm', 'Report'), {
          onclick: () => {
            showView('scanner');
            pollScan(s.id);
          }
        }),
        Object.assign(el('button', 'btn-sm', 'Compare'), {
          onclick: () => setupCompare(s.id)
        }),
      ])
    ]));

    const t = el('table', 'data-table', null, [
      el('tr', null, null, [
        el('th', null, 'URL'), el('th', null, 'Domain'), el('th', null, 'Level'),
        el('th', null, 'Score'), el('th', null, 'Timestamp (UTC)'), el('th', null, 'Actions')
      ]),
      ...rows
    ]);
    container.replaceChildren(t);
  } catch (err) {
    container.replaceChildren(el('div', 'err', err.message));
  }
}

// ============================================================================
// Comparison View
// ============================================================================
function setupCompare(scanId) {
  state.compareBaseId = scanId;
  showView('compare');
  const baseInput = $('compare-base-id');
  if (baseInput) baseInput.value = scanId;
}

async function runComparison() {
  const baseId = $('compare-base-id').value.trim();
  const compId = $('compare-target-id').value.trim();
  const out = $('compare-results');
  if (!baseId || !compId) {
    alert('Please enter both Scan IDs to compare.');
    return;
  }
  out.replaceChildren(el('div', 'empty-state', 'Computing differential telemetry...'));

  try {
    const diff = await api(`/api/v1/scans/compare/${baseId}/${compId}`);
    out.replaceChildren();

    // Summary Delta Card
    const deltaCard = el('div', 'card', null, [
      el('h2', null, 'Delta Summary'),
      el('div', 'top', null, [
        el('div', 'gauge', null, [
          el('div', 'metric-title', 'Threat Score Delta'),
          el('div', 'score', `${diff.threat_score_delta >= 0 ? '+' : ''}${diff.threat_score_delta}`),
          el('div', 'mini', `Hygiene delta: ${diff.hygiene_score_delta >= 0 ? '+' : ''}${diff.hygiene_score_delta}`)
        ]),
        el('div', null, null, [
          el('div', 'summary', `Comparison between Base Scan [${baseId}] and Target Scan [${compId}].`),
          el('div', 'mini', `New findings observed: ${diff.new_findings.length} • Resolved findings: ${diff.resolved_findings.length} • Unchanged: ${diff.unchanged_findings.length}`),
          el('div', 'mini', `Redirect chain changed: ${diff.redirect_chain_changed ? 'YES (Structural modification)' : 'NO'}`)
        ])
      ])
    ]);
    out.appendChild(deltaCard);

    // New Findings Section
    if (diff.new_findings.length) {
      const newItems = diff.new_findings.map(f => el('div', 'f', null, [
        Object.assign(el('span', 'sev', f.severity), { style: `background:${COLORS[f.severity]}` }),
        el('b', null, f.title),
        el('div', 'detail', f.detail)
      ]));
      out.appendChild(section(`New Findings in Compare Scan (+${diff.new_findings.length})`, newItems));
    }

    // Resolved Findings Section
    if (diff.resolved_findings.length) {
      const resItems = diff.resolved_findings.map(f => el('div', 'f', null, [
        Object.assign(el('span', 'sev', f.severity), { style: `background:${COLORS[f.severity]}` }),
        el('b', null, f.title),
        el('div', 'detail', f.detail)
      ]));
      out.appendChild(section(`Resolved Findings (-${diff.resolved_findings.length})`, resItems));
    }

  } catch (err) {
    out.replaceChildren(el('div', 'err', `Comparison failed: ${err.message}`));
  }
}

// ============================================================================
// Bulk Scanner View
// ============================================================================
async function loadBulkJobs() {
  const container = $('bulk-jobs-table-container');
  if (!container) return;
  container.replaceChildren(el('div', 'empty-state', 'Loading bulk jobs...'));

  try {
    const jobs = await api('/api/v1/bulk/jobs');
    if (!jobs.length) {
      container.replaceChildren(el('div', 'empty-state', 'No bulk jobs uploaded yet. Upload a CSV above to begin.'));
      return;
    }

    const rows = jobs.map(j => el('tr', null, null, [
      el('td', 'mono', j.filename),
      el('td', null, String(j.total_urls)),
      el('td', null, `${j.successful_urls} / ${j.total_urls}`),
      el('td', null, String(j.failed_urls)),
      el('td', null, null, [
        el('span', `tag-badge role-${j.status === 'completed' ? 'analyst' : 'admin'}`, j.status)
      ]),
      el('td', 'mini', new Date(j.created_at).toLocaleString())
    ]));

    const table = el('table', 'data-table', null, [
      el('tr', null, null, [
        el('th', null, 'Filename'), el('th', null, 'Total URLs'), el('th', null, 'Success'),
        el('th', null, 'Failed'), el('th', null, 'Status'), el('th', null, 'Uploaded (UTC)')
      ]),
      ...rows
    ]);
    container.replaceChildren(table);
  } catch (err) {
    container.replaceChildren(el('div', 'err', err.message));
  }
}

async function uploadBulkCSV() {
  const input = $('bulk-file-input');
  if (!input.files || !input.files[0]) {
    alert('Please choose a CSV file first.');
    return;
  }
  const file = input.files[0];
  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await api('/api/v1/bulk/upload', {
      method: 'POST',
      body: formData
    });
    alert(`Bulk job queued! Total URLs: ${res.total_urls}. Processing in background.`);
    input.value = '';
    loadBulkJobs();
  } catch (ex) {
    alert(ex.message);
  }
}

// ============================================================================
// Watchlists View
// ============================================================================
async function loadWatchlists() {
  const container = $('watchlists-table-container');
  if (!container) return;
  container.replaceChildren(el('div', 'empty-state', 'Loading watchlists...'));

  try {
    const items = await api('/api/v1/watchlists');
    if (!items.length) {
      container.replaceChildren(el('div', 'empty-state', 'No recurring watchlists configured. Add one above.'));
      return;
    }

    const rows = items.map(w => el('tr', null, null, [
      el('td', null, w.name),
      el('td', 'mono', w.target),
      el('td', null, `${w.interval_minutes} mins`),
      el('td', 'mini', w.last_run_at ? new Date(w.last_run_at).toLocaleString() : 'Never'),
      el('td', 'mini', new Date(w.next_run_at).toLocaleString()),
      el('td', null, null, [
        el('span', `tag-badge role-${w.is_active ? 'analyst' : 'admin'}`, w.is_active ? 'Active' : 'Paused')
      ]),
      el('td', null, null, [
        Object.assign(el('button', 'btn-sm', 'Trigger Now'), {
          onclick: async () => {
            await api(`/api/v1/watchlists/${w.id}/trigger`, { method: 'POST' });
            alert('Watchlist scan triggered!');
            loadWatchlists();
          }
        }),
        Object.assign(el('button', 'btn-sm', w.is_active ? 'Pause' : 'Resume'), {
          onclick: async () => {
            await api(`/api/v1/watchlists/${w.id}/toggle`, { method: 'PATCH' });
            loadWatchlists();
          }
        }),
        Object.assign(el('button', 'btn-sm btn-danger', 'Delete'), {
          onclick: async () => {
            if (confirm(`Delete watchlist "${w.name}"?`)) {
              await api(`/api/v1/watchlists/${w.id}`, { method: 'DELETE' });
              loadWatchlists();
            }
          }
        })
      ])
    ]));

    const table = el('table', 'data-table', null, [
      el('tr', null, null, [
        el('th', null, 'Name'), el('th', null, 'Target'), el('th', null, 'Interval'),
        el('th', null, 'Last Run'), el('th', null, 'Next Run'), el('th', null, 'Status'), el('th', null, 'Actions')
      ]),
      ...rows
    ]);
    container.replaceChildren(table);
  } catch (err) {
    container.replaceChildren(el('div', 'err', err.message));
  }
}

async function addWatchlistTarget() {
  const name = $('wl-name').value.trim();
  const target = $('wl-target').value.trim();
  const interval = parseInt($('wl-interval').value, 10);
  if (!name || !target) {
    alert('Please enter name and target URL/domain.');
    return;
  }
  try {
    await api('/api/v1/watchlists', {
      method: 'POST',
      body: { name, target, interval_minutes: interval }
    });
    $('wl-name').value = '';
    $('wl-target').value = '';
    loadWatchlists();
  } catch (ex) {
    alert(ex.message);
  }
}

// ============================================================================
// Rules View (Allowlist & Blocklist)
// ============================================================================
async function loadRules() {
  await Promise.all([loadBlocklist(), loadAllowlist()]);
}

async function loadBlocklist() {
  const container = $('blocklist-table-container');
  if (!container) return;
  try {
    const rules = await api('/api/v1/rules/blocklist');
    if (!rules.length) {
      container.replaceChildren(el('div', 'empty-state', 'No active blocklist rules.'));
      return;
    }
    const rows = rules.map(r => el('tr', null, null, [
      el('td', 'mono', r.pattern),
      el('td', null, r.pattern_type),
      el('td', null, r.reason),
      el('td', 'mini', new Date(r.created_at).toLocaleDateString()),
      el('td', null, null, [
        Object.assign(el('button', 'btn-sm btn-danger', 'Remove'), {
          onclick: async () => {
            if (confirm(`Remove "${r.pattern}" from blocklist?`)) {
              await api(`/api/v1/rules/blocklist/${r.id}`, { method: 'DELETE' });
              loadBlocklist();
            }
          }
        })
      ])
    ]));
    container.replaceChildren(el('table', 'data-table', null, [
      el('tr', null, null, [el('th', null, 'Pattern'), el('th', null, 'Type'), el('th', null, 'Reason'), el('th', null, 'Added'), el('th', null, 'Action')]),
      ...rows
    ]));
  } catch (e) {
    container.replaceChildren(el('div', 'err', e.message));
  }
}

async function loadAllowlist() {
  const container = $('allowlist-table-container');
  if (!container) return;
  try {
    const rules = await api('/api/v1/rules/allowlist');
    if (!rules.length) {
      container.replaceChildren(el('div', 'empty-state', 'No active allowlist rules.'));
      return;
    }
    const rows = rules.map(r => el('tr', null, null, [
      el('td', 'mono', r.pattern),
      el('td', null, r.pattern_type),
      el('td', null, r.reason),
      el('td', 'mini', new Date(r.created_at).toLocaleDateString()),
      el('td', null, null, [
        Object.assign(el('button', 'btn-sm btn-danger', 'Remove'), {
          onclick: async () => {
            if (confirm(`Remove "${r.pattern}" from allowlist?`)) {
              await api(`/api/v1/rules/allowlist/${r.id}`, { method: 'DELETE' });
              loadAllowlist();
            }
          }
        })
      ])
    ]));
    container.replaceChildren(el('table', 'data-table', null, [
      el('tr', null, null, [el('th', null, 'Pattern'), el('th', null, 'Type'), el('th', null, 'Reason'), el('th', null, 'Added'), el('th', null, 'Action')]),
      ...rows
    ]));
  } catch (e) {
    container.replaceChildren(el('div', 'err', e.message));
  }
}

async function addRule(ruleType) {
  const pattern = $(`${ruleType}-pattern`).value.trim();
  const reason = $(`${ruleType}-reason`).value.trim();
  if (!pattern || !reason) {
    alert('Pattern and reason are required.');
    return;
  }
  try {
    await api(`/api/v1/rules/${ruleType}`, {
      method: 'POST',
      body: { pattern, reason, pattern_type: 'domain' }
    });
    $(`${ruleType}-pattern`).value = '';
    $(`${ruleType}-reason`).value = '';
    if (ruleType === 'blocklist') loadBlocklist();
    else loadAllowlist();
  } catch (ex) {
    alert(ex.message);
  }
}

// ============================================================================
// API Tokens View
// ============================================================================
async function loadTokens() {
  const container = $('tokens-table-container');
  if (!container) return;
  container.replaceChildren(el('div', 'empty-state', 'Loading API tokens...'));

  try {
    const tokens = await api('/api/v1/tokens');
    if (!tokens.length) {
      container.replaceChildren(el('div', 'empty-state', 'No API tokens generated yet. Create one for XDR automation.'));
      return;
    }
    const rows = tokens.map(t => el('tr', null, null, [
      el('td', null, t.name),
      el('td', 'mono', `${t.token_prefix}...`),
      el('td', null, (t.scopes || []).join(', ')),
      el('td', 'mini', t.last_used_at ? new Date(t.last_used_at).toLocaleString() : 'Never'),
      el('td', 'mini', t.expires_at ? new Date(t.expires_at).toLocaleDateString() : 'Never'),
      el('td', null, null, [
        Object.assign(el('button', 'btn-sm btn-danger', 'Revoke'), {
          onclick: async () => {
            if (confirm(`Revoke token "${t.name}"?`)) {
              await api(`/api/v1/tokens/${t.id}`, { method: 'DELETE' });
              loadTokens();
            }
          }
        })
      ])
    ]));
    container.replaceChildren(el('table', 'data-table', null, [
      el('tr', null, null, [el('th', null, 'Name'), el('th', null, 'Prefix'), el('th', null, 'Scopes'), el('th', null, 'Last Used'), el('th', null, 'Expires'), el('th', null, 'Action')]),
      ...rows
    ]));
  } catch (err) {
    container.replaceChildren(el('div', 'err', err.message));
  }
}

async function createApiToken() {
  const name = $('token-name').value.trim();
  if (!name) {
    alert('Please provide a name for this API token.');
    return;
  }
  try {
    const res = await api('/api/v1/tokens', {
      method: 'POST',
      body: { name, scopes: ['scans:read', 'scans:write'], expires_in_days: 90 }
    });
    $('token-name').value = '';
    loadTokens();
    showNewTokenModal(res.token);
  } catch (ex) {
    alert(ex.message);
  }
}

function showNewTokenModal(token) {
  const modal = el('div', 'modal-overlay', null, [
    el('div', 'modal-box', null, [
      el('div', 'modal-header', null, [
        el('h3', null, 'New API Token Generated'),
        Object.assign(el('button', 'close-btn', '×'), { onclick: () => modal.remove() })
      ]),
      el('div', 'mini', 'Copy this token now! You will NOT be able to see it again.'),
      el('div', 'ev', token),
      el('div', 'filter-row', null, [
        Object.assign(el('button', 'btn-sm btn-accent', 'Copy to Clipboard'), {
          onclick: () => {
            navigator.clipboard.writeText(token);
            alert('Token copied!');
          }
        }),
        Object.assign(el('button', 'btn-sm', 'Done'), { onclick: () => modal.remove() })
      ])
    ])
  ]);
  document.body.appendChild(modal);
}

// ============================================================================
// Admin & Audit View
// ============================================================================
async function loadAdminView() {
  if (!state.currentUser || state.currentUser.role !== 'admin') {
    $('view-admin').replaceChildren(el('div', 'empty-state', 'Administrative privileges required.'));
    return;
  }
  await Promise.all([loadAdminUsers(), loadAdminAuditLog(), loadAdminInvitations()]);
}

async function loadAdminUsers() {
  const container = $('admin-users-table');
  if (!container) return;
  try {
    const users = await api('/api/v1/admin/users');
    const rows = users.map(u => el('tr', null, null, [
      el('td', null, u.email),
      el('td', null, null, [
        el('span', `role-badge role-${u.role}`, u.role)
      ]),
      el('td', null, u.is_active ? 'Active' : 'Disabled'),
      el('td', 'mini', new Date(u.created_at).toLocaleDateString()),
      el('td', null, null, [
        Object.assign(el('button', 'btn-sm', u.role === 'admin' ? 'Set Analyst' : 'Set Admin'), {
          onclick: async () => {
            await api(`/api/v1/admin/users/${u.id}`, {
              method: 'PATCH',
              body: { role: u.role === 'admin' ? 'analyst' : 'admin' }
            });
            loadAdminUsers();
          }
        }),
        Object.assign(el('button', 'btn-sm', u.is_active ? 'Disable' : 'Enable'), {
          onclick: async () => {
            await api(`/api/v1/admin/users/${u.id}`, {
              method: 'PATCH',
              body: { role: u.role, is_active: !u.is_active }
            });
            loadAdminUsers();
          }
        })
      ])
    ]));
    container.replaceChildren(el('table', 'data-table', null, [
      el('tr', null, null, [el('th', null, 'Email'), el('th', null, 'Role'), el('th', null, 'Status'), el('th', null, 'Created'), el('th', null, 'Actions')]),
      ...rows
    ]));
  } catch (e) {
    container.replaceChildren(el('div', 'err', e.message));
  }
}

async function loadAdminAuditLog() {
  const container = $('admin-audit-table');
  if (!container) return;
  try {
    const logs = await api('/api/v1/admin/audit-log?limit=30');
    const rows = logs.map(l => el('tr', null, null, [
      el('td', 'mono', l.action),
      el('td', null, l.user_email || 'System'),
      el('td', null, `${l.target_type} ${l.target_id || ''}`),
      el('td', 'mini', l.ip_address || '-'),
      el('td', 'mini', new Date(l.created_at).toLocaleString())
    ]));
    container.replaceChildren(el('table', 'data-table', null, [
      el('tr', null, null, [el('th', null, 'Action'), el('th', null, 'Actor'), el('th', null, 'Target'), el('th', null, 'IP'), el('th', null, 'Timestamp')]),
      ...rows
    ]));
  } catch (e) {
    container.replaceChildren(el('div', 'err', e.message));
  }
}

async function loadAdminInvitations() {
  const container = $('admin-invites-table');
  if (!container) return;
  try {
    const invites = await api('/api/v1/admin/invitations');
    const rows = invites.map(i => el('tr', null, null, [
      el('td', null, i.email),
      el('td', null, i.role),
      el('td', 'mono', `${i.token.slice(0, 16)}...`),
      el('td', 'mini', new Date(i.expires_at).toLocaleDateString()),
      el('td', null, null, [
        Object.assign(el('button', 'btn-sm btn-accent', 'Copy Token'), {
          onclick: () => {
            navigator.clipboard.writeText(i.token);
            alert('Invitation token copied to clipboard!');
          }
        })
      ])
    ]));
    container.replaceChildren(el('table', 'data-table', null, [
      el('tr', null, null, [el('th', null, 'Invited Email'), el('th', null, 'Role'), el('th', null, 'Token'), el('th', null, 'Expires'), el('th', null, 'Action')]),
      ...rows
    ]));
  } catch (e) {
    container.replaceChildren(el('div', 'err', e.message));
  }
}

async function createInvitation() {
  const email = $('invite-email').value.trim();
  const role = $('invite-role').value;
  if (!email) {
    alert('Email is required.');
    return;
  }
  try {
    const res = await api('/api/v1/admin/invitations', {
      method: 'POST',
      body: { email, role, expires_in_days: 7 }
    });
    $('invite-email').value = '';
    loadAdminInvitations();
    alert(`Invitation created! Token: ${res.token}`);
  } catch (ex) {
    alert(ex.message);
  }
}

// ============================================================================
// Auth Modals (Login & Register)
// ============================================================================
function showLoginModal() {
  const existing = document.querySelector('.modal-overlay');
  if (existing) existing.remove();

  const modal = el('div', 'modal-overlay', null, [
    el('div', 'modal-box', null, [
      el('div', 'modal-header', null, [
        el('h3', null, 'Cloud XDR Portal Login'),
        Object.assign(el('button', 'close-btn', '×'), { onclick: () => modal.remove() })
      ]),
      el('form', 'bar', null, [
        Object.assign(el('input', 'filter-input'), { id: 'login-email', type: 'email', placeholder: 'Email (e.g. admin@xdr.local)', required: true, style: 'width:100%' }),
        Object.assign(el('input', 'filter-input'), { id: 'login-pass', type: 'password', placeholder: 'Password', required: true, style: 'width:100%;margin-top:8px' }),
        Object.assign(el('button', 'btn-sm btn-accent', 'Sign In'), { style: 'width:100%;margin-top:12px;height:40px', type: 'submit' }),
        Object.assign(el('button', 'btn-sm', 'Register With Invitation Link'), {
          style: 'width:100%;margin-top:8px', type: 'button',
          onclick: () => { modal.remove(); showRegisterModal(); }
        })
      ])
    ])
  ]);

  modal.querySelector('form').onsubmit = async (e) => {
    e.preventDefault();
    const email = modal.querySelector('#login-email').value.trim();
    const password = modal.querySelector('#login-pass').value;
    try {
      const user = await api('/api/v1/auth/login', {
        method: 'POST',
        body: { email, password }
      });
      state.currentUser = user;
      modal.remove();
      renderUserBar();
      showView(state.activeView);
    } catch (err) {
      alert(err.message);
    }
  };

  document.body.appendChild(modal);
}

function showRegisterModal() {
  const existing = document.querySelector('.modal-overlay');
  if (existing) existing.remove();

  const modal = el('div', 'modal-overlay', null, [
    el('div', 'modal-box', null, [
      el('div', 'modal-header', null, [
        el('h3', null, 'Accept Invitation & Register'),
        Object.assign(el('button', 'close-btn', '×'), { onclick: () => modal.remove() })
      ]),
      el('form', 'bar', null, [
        Object.assign(el('input', 'filter-input'), { id: 'reg-token', type: 'text', placeholder: 'Invitation Token', required: true, style: 'width:100%' }),
        Object.assign(el('input', 'filter-input'), { id: 'reg-email', type: 'email', placeholder: 'Email matching invitation', required: true, style: 'width:100%;margin-top:8px' }),
        Object.assign(el('input', 'filter-input'), { id: 'reg-pass', type: 'password', placeholder: 'Password (min 8 chars)', required: true, style: 'width:100%;margin-top:8px' }),
        Object.assign(el('button', 'btn-sm btn-accent', 'Create Account'), { style: 'width:100%;margin-top:12px;height:40px', type: 'submit' })
      ])
    ])
  ]);

  modal.querySelector('form').onsubmit = async (e) => {
    e.preventDefault();
    const token = modal.querySelector('#reg-token').value.trim();
    const email = modal.querySelector('#reg-email').value.trim();
    const password = modal.querySelector('#reg-pass').value;
    try {
      const user = await api('/api/v1/auth/register', {
        method: 'POST',
        body: { token, email, password }
      });
      state.currentUser = user;
      modal.remove();
      renderUserBar();
      alert('Registration successful! Welcome to Cloud XDR.');
      showView('scanner');
    } catch (err) {
      alert(err.message);
    }
  };

  document.body.appendChild(modal);
}

window.onload = initApp;
