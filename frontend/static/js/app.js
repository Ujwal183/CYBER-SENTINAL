/**
 * 🛡️ Cyber Sentinel - Frontend Application
 * AI-Based Network Intrusion Detection & Mitigation System
 */
const API = window.location.origin + '/api/v1';
const WS_URL = (window.location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + window.location.host + '/ws/alerts';

const CyberSentinel = {
  token: null, user: null, ws: null, charts: {}, refreshTimer: null, sysMonitorTimer: null,
  cpuHistory: [], ramHistory: [], cpuLabels: [], ramLabels: [],

  // ── INIT ──
  init() {
    this.token = localStorage.getItem('cs_token');
    this.user = JSON.parse(localStorage.getItem('cs_user') || 'null');
    if (this.token && this.user) { this.showApp(); } 
    else { this.showLogin(); }
    this.bindEvents();
    this.startClock();
  },

  bindEvents() {
    document.getElementById('login-form').addEventListener('submit', e => { e.preventDefault(); this.login(); });
    document.getElementById('register-form').addEventListener('submit', e => { e.preventDefault(); this.register(); });
    document.getElementById('btn-logout').addEventListener('click', () => this.logout());
    document.getElementById('menu-toggle').addEventListener('click', () => document.getElementById('sidebar').classList.toggle('open'));
    document.getElementById('btn-simulate').addEventListener('click', () => this.simulateThreat());
    document.getElementById('btn-export').addEventListener('click', () => this.exportCSV());
    document.getElementById('chat-input').addEventListener('keypress', e => { if(e.key==='Enter') this.sendChat(); });
    document.getElementById('setting-threshold').addEventListener('input', e => {
      document.getElementById('threshold-val').textContent = e.target.value + '%';
    });
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault(); e.stopPropagation();
        this.navigateTo(item.dataset.page);
      });
    });
  },

  startClock() {
    const tick = () => {
      const el = document.getElementById('topbar-time');
      if(el) el.textContent = new Date().toLocaleTimeString('en-US', {hour12:false});
    };
    tick(); setInterval(tick, 1000);
  },

  // ── AUTH ──
  async login() {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const errEl = document.getElementById('login-error');
    try {
      const res = await this.api('POST', '/auth/login', { username, password }, false);
      this.token = res.access_token;
      this.user = res.user;
      localStorage.setItem('cs_token', this.token);
      localStorage.setItem('cs_user', JSON.stringify(this.user));
      errEl.textContent = '';
      this.showApp();
    } catch(e) {
      errEl.textContent = e.message || 'Invalid credentials';
    }
  },

  toggleRegister(e) {
    e.preventDefault();
    document.getElementById('login-form').classList.toggle('hidden');
    document.getElementById('register-form').classList.toggle('hidden');
    document.getElementById('login-error').textContent = '';
    document.getElementById('register-error').textContent = '';
  },

  async register() {
    const username = document.getElementById('reg-username').value.trim();
    const email = document.getElementById('reg-email').value.trim();
    const password = document.getElementById('reg-password').value;
    const confirm = document.getElementById('reg-confirm').value;
    const fullName = document.getElementById('reg-fullname').value.trim();
    const errEl = document.getElementById('register-error');
    if (!username || !email || !password) { errEl.textContent = 'All fields are required'; return; }
    if (password.length < 6) { errEl.textContent = 'Password must be at least 6 characters'; return; }
    if (password !== confirm) { errEl.textContent = 'Passwords do not match'; return; }
    try {
      const res = await this.api('POST', '/auth/register', { username, email, password, full_name: fullName || null }, false);
      this.token = res.access_token;
      this.user = res.user;
      localStorage.setItem('cs_token', this.token);
      localStorage.setItem('cs_user', JSON.stringify(this.user));
      errEl.textContent = '';
      this.toast('✅ Account created successfully!', 'success');
      this.showApp();
    } catch(e) {
      errEl.textContent = e.message || 'Registration failed';
    }
  },

  logout() {
    this.token = null; this.user = null;
    localStorage.removeItem('cs_token'); localStorage.removeItem('cs_user');
    if(this.ws) this.ws.close();
    this.showLogin();
  },

  showLogin() {
    document.getElementById('login-screen').classList.remove('hidden');
    document.getElementById('app').classList.add('hidden');
  },

  showApp() {
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('app').classList.remove('hidden');
    document.getElementById('display-username').textContent = this.user?.full_name || this.user?.username || 'User';
    document.getElementById('display-role').textContent = this.user?.role || 'viewer';
    document.querySelector('.user-avatar').textContent = (this.user?.username || 'U')[0].toUpperCase();
    this.navigateTo('dashboard');
    this.connectWebSocket();
    // Auto-refresh dashboard every 15 seconds (real data updates frequently)
    if(this.refreshTimer) clearInterval(this.refreshTimer);
    this.refreshTimer = setInterval(() => {
      if(document.getElementById('page-dashboard')?.classList.contains('active')) this.loadDashboard();
    }, 15000);
    // Auto-refresh system monitor every 5 seconds
    if(this.sysMonitorTimer) clearInterval(this.sysMonitorTimer);
    this.sysMonitorTimer = setInterval(() => {
      if(document.getElementById('page-sysmonitor')?.classList.contains('active')) this.loadSysMonitor();
    }, 5000);
  },

  // ── API ──
  async api(method, path, body = null, auth = true) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (auth && this.token) opts.headers['Authorization'] = `Bearer ${this.token}`;
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(API + path, opts);
    if (res.status === 401) { this.logout(); throw new Error('Session expired'); }
    if (!res.ok) { const d = await res.json().catch(()=>({})); throw new Error(d.detail || 'Request failed'); }
    return res.json();
  },

  // ── WEBSOCKET ──
  connectWebSocket() {
    if(this.ws && this.ws.readyState <= 1) return;
    try {
      this.ws = new WebSocket(WS_URL);
      this.ws.onopen = () => console.log('🔌 WebSocket connected (Real Monitor)');
      this.ws.onmessage = (e) => {
        const data = JSON.parse(e.data);
        if (data.type === 'threat_alert') {
          const tag = data.is_real ? '🔴 REAL' : '⚡';
          this.toast(`${tag} ${data.attack_type} from ${data.src_ip}`, 'warning');
          const badge = document.getElementById('threat-badge');
          badge.textContent = parseInt(badge.textContent || 0) + 1;
        } else if (data.type === 'system_health') {
          this._lastSystemHealth = data;
          this.updateSystemHealthBar(data);
          // Push into history for system monitor charts
          const d = data.data || {};
          const now = new Date().toLocaleTimeString('en-US', {hour12:false, hour:'2-digit', minute:'2-digit', second:'2-digit'});
          this.cpuHistory.push(d.cpu_percent || 0);
          this.ramHistory.push(d.memory_percent || 0);
          this.cpuLabels.push(now);
          this.ramLabels.push(now);
          // Keep last 60 data points (10 min at 10s interval)
          if(this.cpuHistory.length > 60) { this.cpuHistory.shift(); this.cpuLabels.shift(); }
          if(this.ramHistory.length > 60) { this.ramHistory.shift(); this.ramLabels.shift(); }
          // Live-update system monitor page if active
          if(document.getElementById('page-sysmonitor')?.classList.contains('active')) {
            this.updateSysMonitorFromWS(data);
          }
        } else if (data.type === 'status') {
          console.log(`[Scan #${data.scan_number}] ${data.message} (${data.connections} conns)`);
        }
      };
      this.ws.onclose = () => {
        console.log('🔌 WebSocket closed, reconnecting...');
        setTimeout(() => this.connectWebSocket(), 5000);
      };
      this.ws.onerror = () => this.ws.close();
    } catch(e) { console.log('WebSocket unavailable'); }
  },

  updateSystemHealthBar(data) {
    let bar = document.getElementById('system-health-bar');
    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'system-health-bar';
      bar.className = 'system-health-bar';
      const topbar = document.querySelector('.topbar-right');
      if (topbar) topbar.prepend(bar);
    }
    const d = data.data || {};
    const cpu = d.cpu_percent || 0;
    const mem = d.memory_percent || 0;
    const conns = (data.network || {}).external_connections || 0;
    bar.innerHTML = `<span title="CPU">🖥 ${cpu}%</span><span title="RAM">💾 ${mem}%</span><span title="External Connections">🌐 ${conns}</span>`;
    bar.style.cssText = 'display:flex;gap:12px;font-size:12px;color:#94a3b8;font-family:JetBrains Mono,monospace;align-items:center;';
  },

  // ── NAVIGATION ──
  navigateTo(page) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const pageEl = document.getElementById('page-' + page);
    const navEl = document.querySelector(`[data-page="${page}"]`);
    if(pageEl) pageEl.classList.add('active');
    if(navEl) navEl.classList.add('active');
    const titles = {dashboard:'SOC Dashboard',sysmonitor:'System Monitor',threats:'Live Threats',blocked:'Blocked IPs',incidents:'Incident Response',models:'AI Model Insights',timeline:'Attack Timeline',chat:'AI Assistant',logs:'Audit Logs',settings:'Settings'};
    document.getElementById('page-title').textContent = titles[page] || page;
    document.getElementById('sidebar').classList.remove('open');
    this.loadPageData(page);
  },

  async loadPageData(page) {
    try {
      if(page==='dashboard') await this.loadDashboard();
      else if(page==='sysmonitor') await this.loadSysMonitor();
      else if(page==='threats') await this.loadThreats();
      else if(page==='blocked') await this.loadBlocked();
      else if(page==='incidents') await this.loadIncidents();
      else if(page==='models') await this.loadModels();
      else if(page==='timeline') await this.loadTimeline();
      else if(page==='logs') await this.loadLogs();
    } catch(e) { console.error('Load error:', e); }
  },

  // ── DASHBOARD ──
  async loadDashboard() {
    const stats = await this.api('GET', '/dashboard/stats');
    document.getElementById('stat-threats-today').textContent = this.formatNum(stats.threats_today);
    document.getElementById('stat-packets').textContent = this.formatNum(stats.active_sessions);
    document.getElementById('stat-blocked').textContent = stats.blocked_ips;
    document.getElementById('stat-accuracy').textContent = stats.model_accuracy + '%';
    document.getElementById('stat-critical').textContent = stats.critical_threats;
    document.getElementById('stat-mitigated').textContent = stats.mitigated_today;
    this.renderWeeklyChart(stats.weekly_trend);
    this.renderCategoriesChart(stats.attack_categories);
    this.renderSeverityChart(stats.severity_distribution);
    this.renderHourlyChart(stats.hourly_trend);
    // Recent threats
    const threats = await this.api('GET', '/threats/live?limit=10');
    const tbody = document.getElementById('recent-threats-body');
    tbody.innerHTML = threats.map(t => `<tr>
      <td>${this.timeAgo(t.timestamp)}</td><td><code>${t.src_ip}</code></td>
      <td>${t.attack_type}</td><td><span class="badge badge-${t.severity}">${t.severity}</span></td>
      <td>${(t.confidence*100).toFixed(1)}%</td>
      <td>${t.is_mitigated?'<span class="badge badge-low">Mitigated</span>':'<span class="badge badge-high">Active</span>'}</td>
    </tr>`).join('');
  },

  // ── CHARTS ──
  renderWeeklyChart(data) {
    this.renderChart('chart-weekly', 'bar', {
      labels: data.map(d=>d.day), datasets: [{label:'Threats',data:data.map(d=>d.count),
      backgroundColor:'rgba(0,240,255,0.3)',borderColor:'#00f0ff',borderWidth:2,borderRadius:6}]
    });
  },
  renderCategoriesChart(data) {
    const colors = ['#ef4444','#f97316','#eab308','#22c55e','#3b82f6','#a855f7','#f43f5e','#06b6d4'];
    this.renderChart('chart-categories', 'doughnut', {
      labels: Object.keys(data), datasets: [{data:Object.values(data),backgroundColor:colors.slice(0,Object.keys(data).length),borderWidth:0,hoverOffset:8}]
    }, {cutout:'60%',plugins:{legend:{position:'right',labels:{color:'#94a3b8',font:{size:11},padding:12}}}});
  },
  renderSeverityChart(data) {
    const colors = {critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22c55e',info:'#3b82f6'};
    this.renderChart('chart-severity', 'polarArea', {
      labels: Object.keys(data).map(s=>s.toUpperCase()), datasets: [{data:Object.values(data),backgroundColor:Object.keys(data).map(k=>colors[k]+'99'),borderWidth:0}]
    }, {plugins:{legend:{position:'right',labels:{color:'#94a3b8'}}}});
  },
  renderHourlyChart(data) {
    this.renderChart('chart-hourly', 'line', {
      labels: data.map(d=>d.hour), datasets: [{label:'Activity',data:data.map(d=>d.count),
      borderColor:'#00ff88',backgroundColor:'rgba(0,255,136,0.1)',fill:true,tension:0.4,pointRadius:2}]
    });
  },
  renderChart(id, type, data, extraOpts={}) {
    if(this.charts[id]) this.charts[id].destroy();
    const ctx = document.getElementById(id);
    if(!ctx) return;
    const isCircular = ['doughnut','pie','polarArea','radar'].includes(type);
    const defaults = {responsive:true, maintainAspectRatio:isCircular, plugins:{legend:{labels:{color:'#94a3b8'}}}, scales:{}};
    if(['bar','line','scatter'].includes(type)) {
      defaults.scales = {x:{ticks:{color:'#64748b'},grid:{color:'rgba(30,41,59,0.5)'}},y:{ticks:{color:'#64748b'},grid:{color:'rgba(30,41,59,0.5)'}}};
    }
    this.charts[id] = new Chart(ctx, {type, data, options:{...defaults,...extraOpts}});
  },

  // ── THREATS ──
  async loadThreats() {
    const sev = document.getElementById('filter-severity')?.value || '';
    const atk = document.getElementById('filter-attack')?.value || '';
    let url = '/threats?per_page=50';
    if(sev) url += `&severity=${sev}`;
    if(atk) url += `&attack_type=${encodeURIComponent(atk)}`;
    const res = await this.api('GET', url);
    const tbody = document.getElementById('threats-body');
    tbody.innerHTML = (res.items||[]).map(t => `<tr>
      <td>#${t.id}</td><td>${this.timeAgo(t.timestamp)}</td>
      <td><code>${t.src_ip}:${t.src_port||'?'}</code></td>
      <td><code>${t.dst_ip}:${t.dst_port||'?'}</code></td>
      <td>${t.attack_type}</td><td><span class="badge badge-${t.severity}">${t.severity}</span></td>
      <td>${t.severity_score}</td><td>${(t.confidence*100).toFixed(1)}%</td>
      <td><button class="btn-danger" onclick="CyberSentinel.blockFromThreat('${t.src_ip}','${t.attack_type}')">Block</button></td>
    </tr>`).join('');
  },

  // ── BLOCKED IPs ──
  async loadBlocked() {
    const ips = await this.api('GET', '/blocked-ips');
    document.getElementById('blocked-body').innerHTML = ips.map(b => `<tr>
      <td><code>${b.ip_address}</code></td><td>${b.reason||'N/A'}</td><td>${b.blocked_by||'System'}</td>
      <td>${b.threat_count}</td><td>${this.timeAgo(b.blocked_at)}</td>
      <td><button class="btn-success" onclick="CyberSentinel.unblockIP('${b.ip_address}')">Unblock</button></td>
    </tr>`).join('');
  },

  async blockFromThreat(ip, reason) {
    try {
      await this.api('POST', '/block/ip', {ip_address:ip, reason:`Blocked: ${reason}`, duration_hours:24});
      this.toast(`🚫 Blocked ${ip}`, 'success');
      this.loadThreats();
    } catch(e) { this.toast(e.message, 'error'); }
  },

  async unblockIP(ip) {
    try {
      await this.api('DELETE', `/block/ip/${ip}`);
      this.toast(`✅ Unblocked ${ip}`, 'success');
      this.loadBlocked();
    } catch(e) { this.toast(e.message, 'error'); }
  },

  showBlockIPModal() {
    document.getElementById('modal-title').textContent = 'Block IP Address';
    document.getElementById('modal-body').innerHTML = `
      <div class="input-group"><label>IP Address</label><input id="modal-ip" placeholder="e.g. 192.168.1.100"></div>
      <div class="input-group"><label>Reason</label><input id="modal-reason" placeholder="Reason for blocking"></div>
      <button class="btn-primary" onclick="CyberSentinel.submitBlockIP()" style="width:100%;margin-top:10px">Block IP</button>`;
    document.getElementById('modal-overlay').classList.remove('hidden');
  },

  async submitBlockIP() {
    const ip = document.getElementById('modal-ip').value;
    const reason = document.getElementById('modal-reason').value;
    if(!ip) return;
    try {
      await this.api('POST', '/block/ip', {ip_address:ip, reason, duration_hours:24});
      this.toast(`🚫 Blocked ${ip}`, 'success');
      this.closeModal(); this.loadBlocked();
    } catch(e) { this.toast(e.message, 'error'); }
  },

  // ── INCIDENTS ──
  async loadIncidents() {
    const incs = await this.api('GET', '/incidents');
    document.getElementById('incidents-body').innerHTML = incs.map(i => `<tr>
      <td><code>${i.incident_id}</code></td><td>${i.title}</td>
      <td><span class="badge badge-${i.severity}">${i.severity}</span></td>
      <td><span class="badge badge-${i.status==='open'?'high':i.status==='closed'?'low':'medium'}">${i.status}</span></td>
      <td>${i.assigned_to||'Unassigned'}</td><td>${this.timeAgo(i.created_at)}</td>
    </tr>`).join('');
  },

  showIncidentModal() {
    document.getElementById('modal-title').textContent = 'Create Incident';
    document.getElementById('modal-body').innerHTML = `
      <div class="input-group"><label>Title</label><input id="modal-inc-title" placeholder="Incident title"></div>
      <div class="input-group"><label>Description</label><textarea id="modal-inc-desc" rows="3" placeholder="Describe the incident"></textarea></div>
      <div class="input-group"><label>Severity</label><select id="modal-inc-sev"><option value="critical">Critical</option><option value="high">High</option><option value="medium" selected>Medium</option><option value="low">Low</option></select></div>
      <button class="btn-primary" onclick="CyberSentinel.submitIncident()" style="width:100%;margin-top:10px">Create Incident</button>`;
    document.getElementById('modal-overlay').classList.remove('hidden');
  },

  async submitIncident() {
    const title = document.getElementById('modal-inc-title').value;
    const desc = document.getElementById('modal-inc-desc').value;
    const sev = document.getElementById('modal-inc-sev').value;
    if(!title) return;
    try {
      await this.api('POST', '/incidents', {title, description:desc, severity:sev});
      this.toast('📋 Incident created', 'success');
      this.closeModal(); this.loadIncidents();
    } catch(e) { this.toast(e.message, 'error'); }
  },

  // ── AI MODELS ──
  async loadModels() {
    const data = await this.api('GET', '/models/performance');
    const grid = document.getElementById('models-grid');
    grid.innerHTML = (data.models||[]).map(m => `<div class="model-card">
      <h4>${m.model_name}</h4>
      <div class="metric-row"><span>Accuracy</span><span>${(m.accuracy*100).toFixed(2)}%</span></div>
      <div class="metric-row"><span>Precision</span><span>${(m.precision*100).toFixed(2)}%</span></div>
      <div class="metric-row"><span>Recall</span><span>${(m.recall*100).toFixed(2)}%</span></div>
      <div class="metric-row"><span>F1 Score</span><span>${(m.f1_score*100).toFixed(2)}%</span></div>
      <div class="metric-row"><span>ROC AUC</span><span>${m.roc_auc?(m.roc_auc*100).toFixed(2)+'%':'N/A'}</span></div>
    </div>`).join('');
    // Feature importance chart
    if(data.feature_importance) {
      const sorted = Object.entries(data.feature_importance).sort((a,b)=>b[1]-a[1]).slice(0,15);
      this.renderChart('chart-features', 'bar', {
        labels: sorted.map(s=>s[0]), datasets:[{label:'Importance',data:sorted.map(s=>s[1]),
        backgroundColor:'rgba(168,85,247,0.4)',borderColor:'#a855f7',borderWidth:1,borderRadius:4}]
      }, {indexAxis:'y'});
    }
  },

  // ── TIMELINE ──
  async loadTimeline() {
    const threats = await this.api('GET', '/threats/live?limit=30');
    const colors = {critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22c55e',info:'#3b82f6'};
    // Chart
    this.renderChart('chart-timeline', 'scatter', {
      datasets: [{label:'Threats',data:threats.map((t,i)=>({x:i,y:t.severity_score})),
      backgroundColor:threats.map(t=>colors[t.severity]||'#3b82f6'),pointRadius:6}]
    });
    // Feed
    document.getElementById('timeline-feed').innerHTML = threats.map(t => `<div class="timeline-item">
      <div class="timeline-dot" style="background:${colors[t.severity]||'#3b82f6'}"></div>
      <div class="timeline-content">
        <strong>${t.attack_type}</strong> from <code>${t.src_ip}</code> → <code>${t.dst_ip}:${t.dst_port||'?'}</code>
        <br><span class="badge badge-${t.severity}">${t.severity}</span> Score: ${t.severity_score}
        <div class="timeline-time">${this.timeAgo(t.timestamp)}</div>
      </div>
    </div>`).join('');
  },

  // ── AI CHAT ──
  async sendChat() {
    const input = document.getElementById('chat-input');
    const msg = input.value.trim(); if(!msg) return;
    input.value = '';
    const container = document.getElementById('chat-messages');
    container.innerHTML += `<div class="chat-msg user"><div class="chat-avatar">👤</div><div class="chat-bubble">${this.esc(msg)}</div></div>`;
    try {
      const res = await this.api('GET', `/chat?message=${encodeURIComponent(msg)}`);
      container.innerHTML += `<div class="chat-msg bot"><div class="chat-avatar">🤖</div><div class="chat-bubble">${this.esc(res.response)}</div></div>`;
    } catch(e) {
      container.innerHTML += `<div class="chat-msg bot"><div class="chat-avatar">🤖</div><div class="chat-bubble">Sorry, I encountered an error.</div></div>`;
    }
    container.scrollTop = container.scrollHeight;
  },

  // ── AUDIT LOGS ──
  async loadLogs() {
    const logs = await this.api('GET', '/audit-logs?limit=100');
    document.getElementById('logs-body').innerHTML = logs.map(l => `<tr>
      <td>${this.timeAgo(l.timestamp)}</td><td>${l.username||'System'}</td>
      <td>${l.action}</td><td>${l.resource||'-'}</td>
      <td><span class="badge badge-${l.status==='success'?'low':'high'}">${l.status}</span></td>
    </tr>`).join('');
  },

  // ── SYSTEM MONITOR (Professional) ──
  netSentHistory: [], netRecvHistory: [], netLabels: [],
  _prevNetSent: 0, _prevNetRecv: 0,

  async loadSysMonitor() {
    try {
      const [system, network] = await Promise.all([
        this.api('GET', '/system/metrics'),
        this.api('GET', '/system/network-summary')
      ]);

      const cpu = system.cpu_percent || 0;
      const ram = system.memory_percent || 0;
      const disk = system.disk_used_percent || 0;
      const totalConns = network.total_connections || 0;
      const circ = 2 * Math.PI * 60;

      // Update ring gauges (r=60)
      this._setRing('sm-ring-cpu', cpu, circ);
      this._setRing('sm-ring-ram', ram, circ);
      this._setRing('sm-ring-disk', disk, circ);
      this._setRing('sm-ring-net', Math.min(totalConns / 2, 100), circ);

      // Update values
      this._setText('sm-cpu-val', cpu + '%');
      this._setText('sm-ram-val', ram + '%');
      this._setText('sm-disk-val', disk + '%');
      this._setText('sm-net-val', totalConns);
      this._setText('sm-cpu-cores', system.cpu_count || '—');
      this._setText('sm-cpu-freq', system.cpu_count ? system.cpu_count + ' cores' : '—');
      this._setText('sm-ram-used', (system.memory_used_gb || 0) + ' GB');
      this._setText('sm-ram-total', (system.memory_total_gb || 0) + ' GB');
      this._setText('sm-disk-used', ((system.disk_used_percent || 0) * (system.disk_total_gb || 0) / 100).toFixed(0) + ' GB');
      this._setText('sm-disk-total', (system.disk_total_gb || 0) + ' GB');
      this._setText('sm-net-ext', network.external_connections || 0);
      this._setText('sm-net-listen', network.listening_ports || 0);

      // Status badges
      this._setStatusBadge('sm-cpu-status', cpu);
      this._setStatusBadge('sm-ram-status', ram);
      this._setStatusBadge('sm-disk-status', disk);
      const netBadge = document.getElementById('sm-net-status');
      if (netBadge) { netBadge.textContent = 'ACTIVE'; netBadge.className = 'sm-gauge-badge'; }

      // Banner
      this._setText('sm-host-name', system.hostname || '—');
      this._setText('sm-os-name', system.os || '—');
      this._setText('sm-uptime', system.uptime_hours ? system.uptime_hours + 'h' : '—');
      this._setText('sm-last-update', 'Last update: ' + new Date().toLocaleTimeString('en-US', {hour12:false}));

      // Health status
      const healthEl = document.getElementById('sm-health-status');
      if (healthEl) {
        if (cpu > 90 || ram > 95) { healthEl.textContent = 'CRITICAL'; healthEl.className = 'sm-banner-status critical'; }
        else if (cpu > 70 || ram > 80) { healthEl.textContent = 'WARNING'; healthEl.className = 'sm-banner-status warning'; }
        else { healthEl.textContent = 'OPERATIONAL'; healthEl.className = 'sm-banner-status'; }
      }

      // Network I/O stats
      this._setText('sm-io-sent', this._fmtBytes(system.net_bytes_sent || 0));
      this._setText('sm-io-recv', this._fmtBytes(system.net_bytes_recv || 0));
      this._setText('sm-io-pkts', this.formatNum(system.net_packets_recv || 0) + ' / ' + this.formatNum(system.net_packets_sent || 0));
      this._setText('sm-io-errors', (system.net_errors_in || 0) + ' / ' + (system.net_errors_out || 0));
      this._setText('sm-unique-ips', network.unique_remote_ips || 0);
      this._setText('sm-highrisk', network.high_risk_listening || 0);

      // Push CPU/RAM history
      const now = new Date().toLocaleTimeString('en-US', {hour12:false, hour:'2-digit', minute:'2-digit', second:'2-digit'});
      if(this.cpuLabels.length === 0 || this.cpuLabels[this.cpuLabels.length-1] !== now) {
        this.cpuHistory.push(cpu); this.ramHistory.push(ram);
        this.cpuLabels.push(now); this.ramLabels.push(now);
        if(this.cpuHistory.length > 60) { this.cpuHistory.shift(); this.cpuLabels.shift(); }
        if(this.ramHistory.length > 60) { this.ramHistory.shift(); this.ramLabels.shift(); }

        // Network throughput delta
        const sentDelta = this._prevNetSent ? Math.max(0, (system.net_bytes_sent - this._prevNetSent) / 5) : 0;
        const recvDelta = this._prevNetRecv ? Math.max(0, (system.net_bytes_recv - this._prevNetRecv) / 5) : 0;
        this._prevNetSent = system.net_bytes_sent;
        this._prevNetRecv = system.net_bytes_recv;
        this.netSentHistory.push(sentDelta / 1024); // KB/s
        this.netRecvHistory.push(recvDelta / 1024);
        this.netLabels.push(now);
        if(this.netSentHistory.length > 60) { this.netSentHistory.shift(); this.netRecvHistory.shift(); this.netLabels.shift(); }
      }

      // CPU chart
      this._renderSmChart('chart-cpu-history', this.cpuLabels, this.cpuHistory, '#00f0ff', 'rgba(0,240,255,0.06)');
      // RAM chart
      this._renderSmChart('chart-ram-history', this.ramLabels, this.ramHistory, '#a855f7', 'rgba(168,85,247,0.06)');
      // Network throughput chart
      this.renderChart('chart-net-throughput', 'line', {
        labels: this.netLabels,
        datasets: [
          { label: '↑ Upload KB/s', data: [...this.netSentHistory], borderColor: '#00f0ff', backgroundColor: 'rgba(0,240,255,0.05)', fill: true, tension: 0.4, pointRadius: 1, borderWidth: 2 },
          { label: '↓ Download KB/s', data: [...this.netRecvHistory], borderColor: '#a855f7', backgroundColor: 'rgba(168,85,247,0.05)', fill: true, tension: 0.4, pointRadius: 1, borderWidth: 2 }
        ]
      }, { scales: {
        y: { min: 0, ticks: { color: '#64748b', callback: v => v.toFixed(0) + ' KB/s' }, grid: { color: 'rgba(30,41,59,0.4)' } },
        x: { ticks: { color: '#64748b', maxTicksLimit: 10 }, grid: { color: 'rgba(30,41,59,0.2)' } }
      }, plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } }, animation: { duration: 400 } });

    } catch(e) { console.error('SysMonitor error:', e); }
  },

  _setRing(id, pct, circ) {
    const el = document.getElementById(id);
    if (!el) return;
    const offset = circ - (circ * Math.min(pct, 100) / 100);
    el.style.strokeDasharray = circ;
    el.style.strokeDashoffset = offset;
  },

  _setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  },

  _setStatusBadge(id, pct) {
    const el = document.getElementById(id);
    if (!el) return;
    if (pct > 90) { el.textContent = 'CRITICAL'; el.className = 'sm-gauge-badge critical'; }
    else if (pct > 70) { el.textContent = 'WARNING'; el.className = 'sm-gauge-badge warning'; }
    else { el.textContent = 'NORMAL'; el.className = 'sm-gauge-badge'; }
  },

  _renderSmChart(canvasId, labels, data, color, bgColor) {
    this.renderChart(canvasId, 'line', {
      labels: labels,
      datasets: [{ label: '', data: [...data], borderColor: color, backgroundColor: bgColor, fill: true, tension: 0.4, pointRadius: 1.5, borderWidth: 2, pointBackgroundColor: color }]
    }, { scales: {
      y: { min: 0, max: 100, ticks: { color: '#64748b', callback: v => v + '%' }, grid: { color: 'rgba(30,41,59,0.4)' } },
      x: { ticks: { color: '#64748b', maxTicksLimit: 10, font: { size: 10 } }, grid: { color: 'rgba(30,41,59,0.2)' } }
    }, plugins: { legend: { display: false } }, animation: { duration: 400 } });
  },

  updateSysMonitorFromWS(data) {
    // Delegate to loadSysMonitor for consistent rendering
    if(document.getElementById('page-sysmonitor')?.classList.contains('active')) {
      this.loadSysMonitor();
    }
  },

  _fmtBytes(b) {
    for (const unit of ['B', 'KB', 'MB', 'GB', 'TB']) {
      if (b < 1024) return b.toFixed(1) + ' ' + unit;
      b /= 1024;
    }
    return b.toFixed(1) + ' PB';
  },

  // ── REAL SCAN ──
  async simulateThreat() {
    try {
      this.toast('🔍 Running real system scan...', 'info');
      const res = await this.api('GET', '/system/scan');
      if (res.threats_found > 0) {
        this.toast(`🔴 Scan complete: ${res.threats_found} real anomalies found!`, 'warning');
      } else {
        this.toast(`✅ Scan complete: System is clean`, 'success');
      }
      if(document.getElementById('page-dashboard').classList.contains('active')) this.loadDashboard();
    } catch(e) { this.toast(e.message, 'error'); }
  },

  // ── EXPORT ──
  async exportCSV() {
    try {
      const res = await this.api('GET', '/threats?per_page=1000');
      const items = res.items || [];
      if(!items.length) { this.toast('No data to export', 'warning'); return; }
      const headers = ['ID','Timestamp','Source IP','Dest IP','Attack Type','Severity','Confidence','Score'];
      const rows = items.map(t=>[t.id,t.timestamp,t.src_ip,t.dst_ip,t.attack_type,t.severity,t.confidence,t.severity_score]);
      const csv = [headers,...rows].map(r=>r.join(',')).join('\n');
      const blob = new Blob([csv], {type:'text/csv'});
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
      a.download = `cyber_sentinel_threats_${new Date().toISOString().slice(0,10)}.csv`;
      a.click(); this.toast('📥 CSV exported', 'success');
    } catch(e) { this.toast(e.message, 'error'); }
  },

  // ── UTILS ──
  closeModal() { document.getElementById('modal-overlay').classList.add('hidden'); },
  formatNum(n) { return n >= 1000 ? (n/1000).toFixed(1)+'k' : String(n||0); },
  esc(s) { const d=document.createElement('div'); d.textContent=s; return d.innerHTML; },
  timeAgo(ts) {
    if(!ts) return 'N/A';
    const diff = (Date.now() - new Date(ts).getTime())/1000;
    if(diff<60) return Math.floor(diff)+'s ago';
    if(diff<3600) return Math.floor(diff/60)+'m ago';
    if(diff<86400) return Math.floor(diff/3600)+'h ago';
    return Math.floor(diff/86400)+'d ago';
  },
  toast(msg, type='info') {
    const container = document.getElementById('toast-container');
    const el = document.createElement('div');
    el.className = `toast toast-${type}`; el.textContent = msg;
    container.appendChild(el);
    setTimeout(() => el.remove(), 5000);
  }
};

// Boot
window.CyberSentinel = CyberSentinel;
document.addEventListener('DOMContentLoaded', () => CyberSentinel.init());
