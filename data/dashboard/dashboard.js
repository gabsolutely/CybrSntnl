const MAX_POINTS = 40;
const HISTORY_POINTS = 60; // For threat history chart

// Store historical data
let threatHistory = [];
let systemData = [];
// Store full session timeline for complete CSV/JSON exports
let sessionHistoryLog = [];
let totalEvents = 0;
let highThreatCount = 0;
let responseStartTime = Date.now();
let lastPacketCount = 0;
let lastPacketTime = Date.now();
let consecutiveFailures = 0;
const SWEEP_GRACE_FAILURES = 2; // require a couple misses before flagging, ignores one-off jitter

// chart colors
const COL_THREAT = "#fb7185";
const COL_ENTROPY= "#0022ff";

// UI elements
const ui = {
  threatVal: document.getElementById('threatVal'),
  classVal: document.getElementById('classVal'),
  rssiVal: document.getElementById('rssiVal'),
  entropyVal: document.getElementById('entropyVal'),
  avg_threat: document.getElementById('avg_threat'),
  avg_rssi: document.getElementById('avg_rssi'),
  avg_entropy: document.getElementById('avg_entropy'),
  packetRateVal: document.getElementById('packetRateVal'),
  packetVal: document.getElementById('packetVal'),
  wifiStatusVal: document.getElementById('wifiStatusVal'),
  wifiIPVal: document.getElementById('wifiIPVal'),
  isrQueueVal: document.getElementById('isrQueueVal'),
  memoryVal: document.getElementById('memoryVal'),
  heapVal: document.getElementById('heapVal'),
  sysUptime: document.getElementById('stat-system-uptime'),
  highThreats: document.getElementById('stat-high-threats'),
  totalEvents: document.getElementById('stat-total-events')
};

// make chart
function makeChart(ctx, label, color) {
  return new Chart(ctx, {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        label: label,
        data: [],
        borderColor: color,
        backgroundColor: color,
        borderWidth: 2,
        pointRadius: 2,
        pointBackgroundColor: color,
        pointHoverRadius: 4,
        tension: 0.25,
        fill: false
      }]
    },
    options: {
      responsive: true,
      animation: false,
      plugins: {
        legend: { display: true, labels: { color: "#e6eef8" }}
      },
      scales: {
        x: {
          display: false,
          ticks: { color: "#9fb0c8" }
        },
        y: {
          display: true,
          ticks: { color: "#9fb0c8" },
          grid: { color: "rgba(255,255,255,0.05)" }
        }
      }
    }
  });
}

// Dynamic Channel Coloring
function applyChannelColoring(channel, mode) {
    const displayEl = document.getElementById("channelDisplay");
    if (!displayEl) return;

    // Neon colors mapped to specific 2.4GHz channels
    const channelColors = {
        1:  "#3498db",
        6:  "#9b59b6",
        11: "#f1c40f",
        // Fallbacks for the in-between channels
        2: "#5dade2", 3: "#1abc9c", 4: "#2ecc71", 5: "#27ae60", 
        7: "#8e44ad", 8: "#e67e22", 9: "#e74c3c", 10: "#c0392b"
    };

    // dynamically as the ESP32 sweeps the spectrum in auto-hop mode.
    displayEl.style.color = channelColors[channel] || "#ffffff";
}

// initialize charts after DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  // Wait longer for dynamic content to load and retry if needed
  function initializeCharts(retryCount = 0) {
    if (retryCount > 3) {
      console.error('Failed to initialize charts after 3 attempts');
      return;
    }
    
    setTimeout(function() {
      // Initialize charts with null checks
      const entropyCanvas = document.getElementById("entropyChart");
      const threatHistoryCanvas = document.getElementById("threatHistoryChart");
      
      console.log("Canvas elements:", {
        entropyCanvas: !!entropyCanvas,
        threatHistoryCanvas: !!threatHistoryCanvas
      });
      
      // Required canvas elements - threatHistoryCanvas is optional
      if (!entropyCanvas) {
        console.warn('Required core canvas elements not found, retrying...');
        initializeCharts(retryCount + 1);
        return;
      }
      
      // Get contexts with defensive null checking
      let entropyCtx, threatHistoryCtx;
      try {
        entropyCtx = entropyCanvas.getContext("2d");
        if (!entropyCtx) throw new Error('Failed to get context for entropyChart');
        
        if (threatHistoryCanvas) {
          threatHistoryCtx = threatHistoryCanvas.getContext("2d");
          if (!threatHistoryCtx) console.warn('Failed to get context for threatHistoryChart');
        } else {
          console.warn('threatHistoryCanvas not found - threat history chart will be disabled');
        }
      } catch (e) {
        console.error('Failed to get canvas contexts:', e);
        initializeCharts(retryCount + 1);
        return;
      }
      const entropyChart= makeChart(entropyCtx, "Entropy", COL_ENTROPY);
      let threatHistoryChart = null;
      if (threatHistoryCtx) {
        threatHistoryChart = makeChart(threatHistoryCtx, "Threat History (60s)", COL_THREAT);
      } else {
        console.warn('Threat history chart disabled - canvas not available');
      }

      // Make charts global so they can be accessed by other functions
      window.entropyChart = entropyChart;
      window.threatHistoryChart = threatHistoryChart;
      
      console.log("Charts initialized successfully");
    }, 500 + (retryCount * 500)); // Increasing delay: 500ms, 1s, 1.5s, 2s
  }
  
  // Start initialization
  initializeCharts();

  // Immediately fetch data as soon as DOM loads
  console.log("DOM loaded, fetching initial data...");
  fetchData();
  fetchEvents();
  fetchSystemInfo();
});

// push and trim new data
function pushTrim(chart, label, value) {
    // Prevent crashes if charts are updating during initial connection handshake
    if (!chart || !chart.data || !chart.data.datasets) {
        return; 
    }
    
    chart.data.labels.push(label);
    chart.data.datasets[0].data.push(value);
    
    if (chart.data.labels.length > 20) { // Keep view scope to 20 points
        chart.data.labels.shift();
        chart.data.datasets[0].data.shift();
    }
    chart.update('none'); // Update without heavy animations for ESP32 performance
}

// logging
function addLog(s){
  const logArea = document.getElementById('logArea');
  if (!logArea) {
    console.error('Log area element not found');
    return;
  }
  const time = new Date().toLocaleTimeString();
  const sanitizedMessage = s.toString().replace(/[<>]/g, '');
  logArea.innerText = `[${time}] ${sanitizedMessage}\n` + logArea.innerText;
  if(logArea.innerText.length > 20000) logArea.innerText = logArea.innerText.slice(0,20000);
}

function showLinkStatusBadge() {
    const el = document.getElementById('channelDisplay');
    if (el) el.dataset.sweeping = "true";
}

function hideLinkStatusBadge() {
    const el = document.getElementById('channelDisplay');
    if (el) el.removeAttribute('data-sweeping');
}

// API Response Validation
function validateApiResponse(data) {
  if (!data || typeof data !== 'object') {
    console.error('Invalid API response: not an object');
    return null;
  }
  
  // Helper to convert strings safely to numbers without throwing errors
  const safeNum = (val) => {
    const parsed = parseFloat(val);
    return isFinite(parsed) ? parsed : 0;
  };
  
  const validated = {
    // --- Core Threat & Anomaly Metrics ---
    threat_score: Math.max(0, Math.min(10, safeNum(data.threat_score))),
    avg_threat:   Math.max(0, Math.min(10, safeNum(data.avg_threat))),
    mac_entropy:  Math.max(0, safeNum(data.mac_entropy)),
    avg_entropy:  Math.max(0, safeNum(data.avg_entropy)),
    avg_rssi:     safeNum(data.avg_rssi),
    
    // --- Threat Classifications ---
    classification:      typeof data.classification === 'string' ? data.classification.replace(/[<>"'&]/g, '').substring(0, 50) : 'UNKNOWN',
    last_classification: typeof data.last_classification === 'string' ? data.last_classification.replace(/[<>"'&]/g, '').substring(0, 50) : 'UNKNOWN',
    
    // --- System Health & Memory Diagnostics ---
    system_status:      typeof data.system_status === 'string' ? data.system_status.replace(/[<>"'&]/g, '').substring(0, 50) : 'UNKNOWN',
    uptime:             safeNum(data.uptime),
    heap_usage_percent: safeNum(data.heap_usage_percent),
    free_heap:          safeNum(data.free_heap),
    isr_queue:          safeNum(data.isr_queue),
    isr_queue_max:      safeNum(data.isr_queue_max) || 1024,
    
    // --- Network Telemetry ---
    packets_processed: safeNum(data.packets_processed),
    packet_rate:       data.packet_rate !== undefined && data.packet_rate !== null ? safeNum(data.packet_rate) : null,
    wifi_status:       typeof data.wifi_status === 'string' ? data.wifi_status.replace(/[<>"'&]/g, '').substring(0, 50) : 'Unknown',
    wifi_ip:           typeof data.wifi_ip === 'string' ? data.wifi_ip.replace(/[<>"'&]/g, '').substring(0, 50) : 'Unknown',
    
    // --- Frequency & Radio Configuration ---
    current_channel: safeNum(data.current_channel) || 1,
    channel_mode:    typeof data.channel_mode === 'string' ? data.channel_mode.substring(0, 20) : 'UNKNOWN'
  };
  
  return validated;
}

// fetch and display data
async function fetchData() {
    try {
        const t = new Date().toLocaleTimeString();
        const dataRes = await fetch("/data", { cache: 'no-store' });
        if (!dataRes.ok) throw new Error('data fetch failed');
        const d = await dataRes.json();

        // Validate
        const validatedData = validateApiResponse(d);
        if (!validatedData) throw new Error('Invalid API response data');

        // Link recovered from a sweep-induced gap
        if (consecutiveFailures >= SWEEP_GRACE_FAILURES) {
            addLog("📡 Link restored after radio sweep");
            hideLinkStatusBadge();
        }
        consecutiveFailures = 0;

        // 2. Math first, calculate Dynamic Packet Rate before we use it
        const now = Date.now();
        let currentRate = validatedData.packet_rate;
        if (currentRate === null || currentRate === undefined) {
            const deltaSec = (now - lastPacketTime) / 1000;
            if (deltaSec > 0) {
                currentRate = Math.max(0, Math.round((validatedData.packets_processed - lastPacketCount) / deltaSec));
            } else {
                currentRate = 0;
            }
        }
        lastPacketCount = validatedData.packets_processed;
        lastPacketTime = now;

        // 3. Threat logic, trusting the tightly-coupled backend classification
        let displayClass = validatedData.classification.toUpperCase();
        let classColor = "#10B981"; // Default Green (SAFE)
        let lightClass = "safe";

        if (displayClass === "CRITICAL") {
            classColor = "#EF4444"; // Red
            lightClass = "critical";
        } else if (displayClass === "ELEVATED") {
            classColor = "#F59E0B"; // Orange
            lightClass = "elevated";
        } else if (displayClass === "WARNING") {
            classColor = "#EAF63B"; // Yellow
            lightClass = "low";
        }

        // Trigger the visual UI alerts if a critical event is coming down the pipe
        if (displayClass === "CRITICAL") {
            triggerThreatAlert(displayClass, "High-velocity anomaly detected on active channel.");
        }

        // UI updates
        if (ui.classVal) {
            ui.classVal.innerText = displayClass;
            ui.classVal.style.color = classColor;
        }
        
        // Target the dot and apply the new CSS class
        const actionLight = document.getElementById('actionLight');
        if (actionLight) {
            actionLight.className = `action-light ${lightClass}`;
        }

        if (ui.threatVal) ui.threatVal.innerText = validatedData.threat_score.toFixed(1);
        if (ui.classVal) {
            ui.classVal.innerText = displayClass;
            ui.classVal.style.color = classColor;
        }
        if (ui.rssiVal) ui.rssiVal.innerText = validatedData.avg_rssi.toFixed(1) + ' dBm';
        if (ui.entropyVal) ui.entropyVal.innerText = validatedData.mac_entropy.toFixed(2);
        
        // Inside your UI render loop / update function:
        if (ui.avg_threat) ui.avg_threat.innerText = `avg ${validatedData.avg_threat.toFixed(1)}`;
        if (ui.avg_rssi) ui.avg_rssi.innerText = `avg ${validatedData.avg_rssi.toFixed(1)}`;
        if (ui.avg_entropy) ui.avg_entropy.innerText = `avg ${validatedData.avg_entropy.toFixed(2)}`;

        // Using our safely calculated currentRate
        if (ui.packetRateVal) ui.packetRateVal.innerText = currentRate.toFixed(1) + ' pkts/s';
        
        if (ui.packetVal) ui.packetVal.innerText = (validatedData.packets_processed || 0).toLocaleString();
        if (ui.wifiStatusVal) ui.wifiStatusVal.innerText = validatedData.wifi_status;
        if (ui.wifiIPVal) ui.wifiIPVal.innerText = "IP: " + validatedData.wifi_ip;
        if (ui.isrQueueVal) ui.isrQueueVal.innerText = validatedData.isr_queue + ' / ' + validatedData.isr_queue_max;
        if (ui.memoryVal) ui.memoryVal.innerText = validatedData.heap_usage_percent.toFixed(1) + "%";
        if (ui.heapVal) ui.heapVal.innerText = "Free: " + validatedData.free_heap.toLocaleString() + " B";
        
        if (ui.sysUptime) {
            const minutes = Math.floor(validatedData.uptime / 60);
            const seconds = validatedData.uptime % 60;
            ui.sysUptime.innerText = `${minutes}m ${seconds}s`;
        }
        
        if (validatedData.threat_score >= 7.5) {
            highThreatCount++;
            if (ui.highThreats) ui.highThreats.innerText = highThreatCount;
        }
        
        if (ui.totalEvents) ui.totalEvents.innerText = validatedData.packets_processed;

        updateHealthScore(validatedData);
        updateThreatHistory(validatedData);
        
        // =========================================================================
        // UI UPDATES & TRIGGER COLOR ENGINE
        // =========================================================================
        const channelDisplayEl = document.getElementById('channelDisplay');
        if (channelDisplayEl) {
            const modeLabel = validatedData.channel_mode === "SCANNING" ? "Auto-Hopping" : 
                              validatedData.channel_mode === "LOCKED" ? "⚠️ THREAT LOCK" : "Manual";
            channelDisplayEl.innerText = `${modeLabel} (Ch ${validatedData.current_channel})`;
            
            applyChannelColoring(validatedData.current_channel, validatedData.channel_mode);
        }

        // =========================================================================
        // SAFE SESSION LOGGING (Variables are now fully initialized!)
        // =========================================================================
        sessionHistoryLog.push({
            time: t,
            channel: validatedData.current_channel,
            mode: validatedData.channel_mode,
            threat: validatedData.threat_score.toFixed(1),
            classification: displayClass,
            rssi: validatedData.avg_rssi.toFixed(1),
            entropy: validatedData.mac_entropy.toFixed(2),
            velocity: currentRate.toFixed(1)
        });

        // Update statistics
        updateStatistics(validatedData);
        
        // Prevent browser memory leaks (cap at 5,000 logs)
        if (sessionHistoryLog.length > 5000) sessionHistoryLog.shift();

        // Update charts
        try {
            if (window.entropyChart) pushTrim(window.entropyChart, t, validatedData.mac_entropy);
        } catch (chartError) {
            console.error('Chart update error:', chartError);
        }

        if (validatedData.threat_score > 0) {
            addLog(`Threat: ${validatedData.threat_score.toFixed(1)} (${displayClass})`);
        }

    } catch (e) {
        console.error("Fetch Data Error:", e);
        consecutiveFailures++;
        if (consecutiveFailures === SWEEP_GRACE_FAILURES) {
            addLog("📡 Radio sweeping spectrum — resyncing shortly");
            showLinkStatusBadge();
        }
    }
}

// Update statistics panel
function updateStatistics(data) {
  totalEvents++;
  
  const responseTime = Date.now() - responseStartTime;
  responseStartTime = Date.now();
  
  // Add null checks for statistics elements
  const totalEventsEl = document.getElementById('totalEvents');
  const highThreatsEl = document.getElementById('highThreats');
  const systemUptimeEl = document.getElementById('systemUptime');
  const responseTimeEl = document.getElementById('responseTime');
  
  if (totalEventsEl) totalEventsEl.innerText = totalEvents;
  if (highThreatsEl) highThreatsEl.innerText = highThreatCount;
  if (systemUptimeEl) systemUptimeEl.innerText = Math.floor(data.uptime / 60) + 'm';
  if (responseTimeEl) responseTimeEl.innerText = responseTime + 'ms';
}

// System Health Score Calculation
function updateHealthScore(data) {
  let healthScore = 100;
  let healthLevel = 'EXCELLENT';
  
  // Validate input data and extract values safely
  const threatScore = typeof data.threat_score === 'number' && isFinite(data.threat_score) ? data.threat_score : 0;
  const uptime = typeof data.uptime === 'number' && isFinite(data.uptime) && data.uptime >= 0 ? data.uptime : 0;
  const systemStatus = data.system_status || 'UNKNOWN';
  const isrQueue = typeof data.isr_queue === 'number' && isFinite(data.isr_queue) ? data.isr_queue : 0;
  const isrQueueMax = typeof data.isr_queue_max === 'number' && isFinite(data.isr_queue_max) ? data.isr_queue_max : 1024;
  
  // 1. Fair Threat Scaling (40% weight) - Deducts 10% per threat point instead of a brutal 20%
  const threatImpact = Math.max(0, Math.min(100, 100 - (threatScore * 10)));
  
  // 2. Factor in system status (30% weight)
  let statusScore = 100;
  if (systemStatus === 'LOW_MEMORY') statusScore = 60;
  else if (systemStatus === 'API_ERRORS') statusScore = 70;
  else if (systemStatus === 'GOOD') statusScore = 100;
  else statusScore = 50; 
  
  // 3. Realistic Uptime Stability (30% weight) - Changed warm-up from 60 mins to a realistic 5 mins for dev cycles
  const uptimeMinutes = uptime / 60;
  const uptimeStabilityScore = Math.min(100, uptimeMinutes > 5 ? 100 : (uptimeMinutes / 5 * 100));
  
  // Base weighted average calculation
  healthScore = (threatImpact * 0.4) + (statusScore * 0.3) + (uptimeStabilityScore * 0.3);
  
  // 4. Dynamic Buffer Overload Penalty - Only punishes the system if the ring buffer fills past 80% capacity
  const queueLoadRatio = isrQueue / isrQueueMax;
  if (queueLoadRatio > 0.8) {
    healthScore -= (queueLoadRatio * 20); 
  }
  
  // Keep health within strict 0-100 bounds
  healthScore = Math.max(0, Math.min(100, healthScore));
  
  // Determine health level
  if (healthScore >= 90) healthLevel = 'EXCELLENT';
  else if (healthScore >= 75) healthLevel = 'GOOD';
  else if (healthScore >= 60) healthLevel = 'FAIR';
  else if (healthScore >= 40) healthLevel = 'POOR';
  else healthLevel = 'CRITICAL';
  
  // Update UI elements with null checks
  const healthScoreEl = document.getElementById('healthScore');
  const healthFillEl = document.getElementById('healthFill');
  
  if (healthScoreEl) healthScoreEl.innerText = Math.round(healthScore) + '%';
  if (healthFillEl) {
    healthFillEl.style.width = healthScore + '%';
    healthFillEl.className = 'health-fill';
    
    if (healthLevel === 'POOR' || healthLevel === 'CRITICAL') {
      healthFillEl.classList.add('danger');
    } else if (healthLevel === 'FAIR') {
      healthFillEl.classList.add('warning');
    } else {
      healthFillEl.classList.add('success');
    }
  }
}

// Threat History Chart
function updateThreatHistory(data) {
  const timestamp = new Date().toLocaleTimeString();
  
  // Validate data before adding to history
  const threatScore = typeof data.threat_score === 'number' && isFinite(data.threat_score) ? data.threat_score : 0;
  
  // Add to history
  threatHistory.push({
    time: timestamp,
    threat: threatScore,
  });
  
  // Keep only last 60 data points
  if (threatHistory.length > HISTORY_POINTS) {
    threatHistory.shift();
  }
  
  // Update chart with error handling
  try {
    if (window.threatHistoryChart && typeof window.threatHistoryChart !== 'null' && window.threatHistoryChart.data && window.threatHistoryChart.data.datasets) {
      window.threatHistoryChart.data.labels = threatHistory.map(h => h.time);
      window.threatHistoryChart.data.datasets[0].data = threatHistory.map(h => h.threat);
      window.threatHistoryChart.update('none');
    } else {
      
    }
  } catch (chartError) {
    console.error('Threat history chart update error:', chartError);
    addLog('Threat history chart update failed');
  }
}

// Upgraded Export Functions
function exportData(format) {
    try {
        if (sessionHistoryLog.length === 0) {
            addLog("⚠️ Export failed: No session data collected yet.");
            return;
        }

        if (format === 'json') {
            const blob = new Blob([JSON.stringify(sessionHistoryLog, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `cybersentinel-session-${Date.now()}.json`;
            a.click();
            URL.revokeObjectURL(url);
            
        } else if (format === 'csv') {
            const headers = "Timestamp,Channel,Mode,Threat Score,Classification,RSSI (dBm),MAC Entropy,Packet Velocity (pkts/s)";
            const rows = sessionHistoryLog.map(r => `"${r.time}",${r.channel},"${r.mode}",${r.threat},"${r.classification}",${r.rssi},${r.entropy},${r.velocity}`);
            const csvContent = `${headers}\n${rows.join('\n')}`;
            const blob = new Blob([csvContent], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `cybersentinel-session-${Date.now()}.csv`;
            a.click();
            URL.revokeObjectURL(url);
            
        } else if (format === 'report') {
            const latest = sessionHistoryLog[sessionHistoryLog.length - 1];
            
            // Extract statistics safely
            const uptime = document.getElementById('stat-system-uptime')?.innerText || 'Active Session';
            const totalEventsText = document.getElementById('stat-total-events')?.innerText || totalEvents || '0';
            const highThreatsText = document.getElementById('stat-high-threats')?.innerText || highThreatCount || '0';

            // Retrieve history from the UI safely
            const logArea = document.getElementById('logArea');
            const historyDump = logArea ? logArea.innerText : "No anomalous transitions detected.";

            const reportContent = 
`==================================================
🛡️ CYBERSENTINEL CORE SECURITY - SESSION REPORT
Generated: ${new Date().toLocaleString()}
==================================================

[1] EXECUTIVE SESSION SUMMARY
--------------------------------------------------
System Operational Status : OPERATIONAL (GOOD)
Total Session Ticks       : ${sessionHistoryLog.length} ticks logged
Total Airspace Activity   : ${totalEventsText} frames processed
High-Risk Threat Triggers : ${highThreatsText} anomalies detected
System Uptime             : ${uptime}

[2] HISTORICAL TELEMETRY AVERAGES
--------------------------------------------------
Rolling Threat Index      : ${latest.threat} / 10
Signal Baseline (RSSI)    : ${latest.rssi} dBm
Mean MAC Address Entropy  : ${latest.entropy}
Packet Velocity           : ${latest.velocity} pkts/s
Final Threat Evaluation   : [ ${latest.classification} ]

[3] ANOMALY EVENT LOG
--------------------------------------------------
${historyDump}
==================================================
END OF TELEMETRY DATA REPOSITORY REPORT
==================================================`;

            const blob = new Blob([reportContent], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `cybersentinel-report-${Date.now()}.txt`;
            a.click();
            URL.revokeObjectURL(url);
        }
        addLog(`Exported full ${format.toUpperCase()} session log successfully`);
    } catch (err) {
        console.error("Export processing error:", err);
        addLog("Export error occurred");
    }
}

// fetch events for log
async function fetchEvents() {
    try {
        const res = await fetch("/events", { cache: 'no-store' });
        if (!res.ok) throw new Error("Event API stream offline");
        
        const contentType = res.headers.get("content-type");
        if (contentType && contentType.includes("application/json")) {
            const eventList = await res.json();
            // Handle parsing array logs if your ESP32 packages them as JSON lists
            if (Array.isArray(eventList)) {
                eventList.forEach(evt => addLog(evt));
            }
        } else {
            // Fallback for raw string logs emitted straight from print statements
            const rawText = await res.text();
            if (rawText.trim()) {
                addLog(rawText.trim());
            }
        }
    } catch (e) {
        console.error("Event system polling error:", e);
        // Suppresses aggressive error logging to keep your terminal visible
    }
}

// fetch comprehensive system information
async function fetchSystemInfo(){
  try{
    const sysRes = await fetch("/system", {cache:'no-store'});
    if (!sysRes.ok) throw new Error('system fetch failed');
    const sys = await sysRes.json();

    // Helper to safely update text
    const update = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.innerText = val;
    };

    update('perfInfo', `CPU: ${sys.performance.cpu_freq}MHz\nHeap: ${sys.free_heap.toLocaleString()} bytes (${sys.heap_usage}%)\nFlash: ${sys.performance.flash_size / 1024 / 1024}MB\nFree Sketch: ${sys.performance.free_sketch / 1024}KB`);
    update('networkInfo', `Status: ${sys.wifi.connected ? 'Connected' : 'AP Mode'}\nIP: ${sys.wifi.ip}\nRSSI: ${sys.wifi.rssi} dBm\nAccess: ${sys.network_access}`);
    
    let storageInfo = `Status: ${sys.spiffs.ready ? 'Ready' : 'Failed'}\nFiles: ${sys.spiffs.files.length} total\n`;
    sys.spiffs.files.forEach(file => {
      storageInfo += `${file.name}: ${file.size} bytes\n`;
    });
    update('storageInfo', storageInfo);

    let apiInfo = '';
    sys.api_endpoints.forEach(endpoint => {
      apiInfo += `${endpoint.endpoint}: ${endpoint.status}\n`;
    });
    update('apiInfo', apiInfo);

  }catch(e){
    console.error('System info fetch error:', e);
  }
}

// periodic fetching
setInterval(fetchData, 2500);
setInterval(fetchEvents, 7500);  // Less frequent for events
setInterval(fetchSystemInfo, 15000); // Update system info every 15 seconds

// Show notification badge
function showNotificationBadge(level, message) {
  const container = document.getElementById('notificationContainer');

  const badge = document.createElement('div');
  badge.className = 'notification-badge';
  
  // Sanitize inputs to prevent XSS
  const sanitizedLevel = (level || '').toString().replace(/[<>"'&]/g, '');
  const sanitizedMessage = (message || '').toString().replace(/[<>"'&]/g, '');
  
  badge.innerHTML = `
    <div class="notification-icon">!</div>
    ${sanitizedLevel}
  `;

  container.appendChild(badge);

  // Auto-remove after 4 seconds
  setTimeout(() => {
    if (badge.parentNode) {
      badge.parentNode.removeChild(badge);
    }
  }, 4000);
}

// Request notification permission
if ('Notification' in window && Notification.permission === 'default') {
  Notification.requestPermission();
}

// Threat alert system
function triggerThreatAlert(level, message) {
  // Border pulse for critical threats
  const alert = document.getElementById('threatAlert');
  
  // Only trigger the alert for critical threats to avoid overwhelming the user
  if (level === 'CRITICAL') {
    alert.style.display = 'block';
    setTimeout(() => {
      alert.style.display = 'none';
    }, 1000);
  }

  // Show browser notification
  if ('Notification' in window && Notification.permission === 'granted') {
    new Notification('CyberSentinel Detection: ' + level, {
      body: message,
      icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="45" fill="%23ef4444"/><text x="50" y="60" text-anchor="middle" fill="white" font-size="40">!</text></svg>',
      tag: 'threat-alert'
    });
  }

  // Show notification badge
  showNotificationBadge(level, message);
}

// Handle channel change
async function handleChannelChange(value) {
    try {
        let url = "";
        if (value === "auto") {
            addLog("Channel Mode: Activating Spectrum Scan...");
            url = '/set_channel?mode=auto';
        } else {
            addLog(`Channel Mode: Locking onto Manual Channel ${value}`);
            url = `/set_channel?mode=manual&ch=${value}`;
        }
        
        const response = await fetch(url, { method: 'GET', cache: 'no-store' });
        if (!response.ok) throw new Error("Hardware rejected control frame");
        
    } catch (e) {
        console.error("Error updating channel configurations:", e);
        addLog("⚠️ Channel control sync failed");
    }
}