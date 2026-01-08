// Network Monitor Dashboard JavaScript

// Global variables
let socket;
let trafficChart;
let alertPieChart;
let packetsGauge, alertsGauge, cpuGauge, memoryGauge, diskGauge;

// Threat Type Information Database
const THREAT_INFO = {
    'PORT_SCAN': {
        name: 'Port Scan',
        description: 'Een aanvaller scant systematisch meerdere poorten op een systeem om open services te vinden.',
        impact: 'HOOG - Dit is vaak de eerste stap in een aanval. Geeft aanvaller informatie over kwetsbare services.',
        icon: 'bi-radar',
        color: '#dc3545'
    },
    'CONNECTION_FLOOD': {
        name: 'Connection Flood',
        description: 'Overmatig aantal connectie-pogingen in korte tijd, mogelijk DDoS aanval of gecompromitteerd systeem.',
        impact: 'CRITICAL - Kan services overweldigen en offline halen. Resource uitputting.',
        icon: 'bi-tsunami',
        color: '#dc3545'
    },
    'DNS_TUNNELING': {
        name: 'DNS Tunneling',
        description: 'Verdacht DNS verkeer dat mogelijk gebruikt wordt om data te exfiltreren of C&C communicatie te verbergen.',
        impact: 'HOOG - Data exfiltratie, command & control communicatie, bypassing van firewalls.',
        icon: 'bi-diagram-3',
        color: '#fd7e14'
    },
    'LARGE_PACKET': {
        name: 'Large Packet',
        description: 'Ongebruikelijk grote pakketten die kunnen wijzen op data exfiltratie of buffer overflow pogingen.',
        impact: 'MEDIUM - Mogelijke data diefstal of exploit poging.',
        icon: 'bi-box-arrow-up',
        color: '#ffc107'
    },
    'BLACKLIST_IP': {
        name: 'Blacklisted IP',
        description: 'Communicatie met een IP adres dat bekend staat als malicious (malware C&C, phishing, etc).',
        impact: 'CRITICAL - Gecompromitteerd systeem. Mogelijke malware infectie of data breach.',
        icon: 'bi-shield-x',
        color: '#dc3545'
    },
    'THREAT_FEED_MATCH': {
        name: 'Threat Feed Match',
        description: 'Match met bekende Indicator of Compromise (IOC) uit threat intelligence feeds.',
        impact: 'CRITICAL - Zeer waarschijnlijk gecompromitteerd. Malware communicatie gedetecteerd.',
        icon: 'bi-exclamation-octagon',
        color: '#dc3545'
    },
    'BEACONING_DETECTED': {
        name: 'Beaconing',
        description: 'Regelmatige, periodieke verbindingen naar externe server - typisch gedrag van malware.',
        impact: 'CRITICAL - Zeer sterke indicatie van malware infectie. C&C communicatie actief.',
        icon: 'bi-broadcast',
        color: '#dc3545'
    },
    'HIGH_OUTBOUND_VOLUME': {
        name: 'High Outbound Volume',
        description: 'Ongewoon hoog uitgaand verkeer, mogelijke data exfiltratie.',
        impact: 'HOOG - Data diefstal in uitvoering. Database dump, bestandsdiefstal.',
        icon: 'bi-upload',
        color: '#fd7e14'
    },
    'LATERAL_MOVEMENT': {
        name: 'Lateral Movement',
        description: 'Intern systeem scant andere interne systemen - typisch voor aanvallers die netwerk verkennen.',
        impact: 'CRITICAL - Actieve aanval in uitvoering. Aanvaller beweegt door netwerk.',
        icon: 'bi-arrows-move',
        color: '#dc3545'
    },
    'BRUTE_FORCE_ATTEMPT': {
        name: 'Brute Force Attempt',
        description: 'Herhaalde login pogingen op authenticatie services (SSH, RDP, FTP, etc.).',
        impact: 'HOOG - Aanvaller probeert in te breken via wachtwoord gissen. Mogelijk compromittering.',
        icon: 'bi-key',
        color: '#dc3545'
    },
    'HTTP_NON_STANDARD_PORT': {
        name: 'HTTP on Non-Standard Port',
        description: 'HTTP verkeer gedetecteerd op ongebruikelijke poort - mogelijke verberging van malware traffic.',
        impact: 'MEDIUM - Mogelijk bypassing van security controls, verborgen communicatie.',
        icon: 'bi-globe',
        color: '#ffc107'
    },
    'SSH_NON_STANDARD_PORT': {
        name: 'SSH on Non-Standard Port',
        description: 'SSH verkeer op andere poort dan 22 - mogelijk backdoor of verborgen toegang.',
        impact: 'MEDIUM - Mogelijk ongeautoriseerde remote access, backdoor.',
        icon: 'bi-terminal',
        color: '#ffc107'
    },
    'DNS_NON_STANDARD_PORT': {
        name: 'DNS on Non-Standard Port',
        description: 'DNS verkeer op andere poort dan 53 - sterke indicator voor DNS tunneling.',
        impact: 'HOOG - Mogelijk DNS tunneling voor C&C communicatie of data exfiltratie.',
        icon: 'bi-diagram-2',
        color: '#fd7e14'
    },
    'FTP_NON_STANDARD_PORT': {
        name: 'FTP on Non-Standard Port',
        description: 'FTP verkeer op ongebruikelijke poort - mogelijke verborgen data transfer.',
        impact: 'MEDIUM - Mogelijk ongeautoriseerde data transfers.',
        icon: 'bi-file-earmark-arrow-up',
        color: '#ffc107'
    },
    'ABUSEIPDB_HIGH_SCORE': {
        name: 'AbuseIPDB High Score',
        description: 'IP adres met hoge abuse score op AbuseIPDB - gerapporteerd door meerdere bronnen.',
        impact: 'HOOG - Bekend malicious IP. Scanners, brute force attacks, spam.',
        icon: 'bi-database-exclamation',
        color: '#fd7e14'
    }
};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    console.log('[DASHBOARD] Starting initialization...');
    const startTime = Date.now();

    // Update loading message
    updateLoadingMessage('Connecting to server...');

    // Initialize WebSocket
    console.log('[DASHBOARD] Step 1/3: Initializing WebSocket...');
    initWebSocket();
    updateLoadingMessage('Initializing charts...');

    // Initialize charts
    console.log('[DASHBOARD] Step 2/3: Initializing charts...');
    initCharts();
    updateLoadingMessage('Loading data...');

    // Initialize configuration management
    console.log('[DASHBOARD] Step 2.5/3: Initializing configuration management...');
    if (typeof initConfigManagement === 'function') {
        initConfigManagement();
    }

    // Load initial data
    console.log('[DASHBOARD] Step 3/3: Loading initial data...');
    loadDashboardData().finally(() => {
        const elapsed = Date.now() - startTime;
        console.log(`[DASHBOARD] Initialization complete in ${elapsed}ms`);
    });

    // Update clock
    updateClock();
    setInterval(updateClock, 1000);

    // Auto-refresh data every 30 seconds
    setInterval(loadDashboardData, 30000);
});

function updateLoadingMessage(message, hint = null) {
    const msgEl = document.getElementById('loading-message');
    const hintEl = document.getElementById('loading-hint');
    if (msgEl) msgEl.textContent = message;
    if (hintEl && hint) hintEl.textContent = hint;
}

// ==================== WebSocket ====================

function initWebSocket() {
    socket = io();

    socket.on('connect', function() {
        console.log('WebSocket connected');
        updateConnectionStatus(true);
    });

    socket.on('disconnect', function() {
        console.log('WebSocket disconnected');
        updateConnectionStatus(false);
    });

    socket.on('connected', function(data) {
        console.log('Server confirmed connection:', data);
    });

    socket.on('new_alert', function(alert) {
        console.log('New alert received:', alert);
        addAlertToFeed(alert, true);
        playAlertSound(alert.severity);
    });

    socket.on('metrics_update', function(metrics) {
        console.log('[WEBSOCKET] Live metrics received:', {
            pps: metrics.traffic?.packets_per_second,
            apm: metrics.traffic?.alerts_per_minute,
            cpu: metrics.system?.cpu_percent,
            memory: metrics.system?.memory_percent
        });
        updateMetrics(metrics);
    });

    socket.on('dashboard_update', function(data) {
        console.log('Dashboard update received');
        updateDashboard(data);
    });

    socket.on('config_updated', function(data) {
        console.log('Configuration updated:', data);
        if (typeof handleConfigUpdate === 'function') {
            handleConfigUpdate(data);
        }
    });

    socket.on('config_reset', function(data) {
        console.log('Configuration reset:', data);
        if (typeof handleConfigReset === 'function') {
            handleConfigReset(data);
        }
    });

    socket.on('error', function(error) {
        console.error('WebSocket error:', error);
    });
}

function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connection-status');
    if (connected) {
        statusEl.className = 'badge bg-success me-3';
        statusEl.innerHTML = '<i class="bi bi-wifi"></i> Connected';
    } else {
        statusEl.className = 'badge bg-danger me-3 disconnected';
        statusEl.innerHTML = '<i class="bi bi-wifi-off"></i> Disconnected';
    }
}

// ==================== Data Loading ====================

async function loadDashboardData() {
    const fetchStart = Date.now();
    console.log('[API] Fetching dashboard data...');

    try {
        const response = await fetch('/api/dashboard');
        const fetchTime = Date.now() - fetchStart;
        console.log(`[API] Response received in ${fetchTime}ms`);

        const parseStart = Date.now();
        const result = await response.json();
        const parseTime = Date.now() - parseStart;
        console.log(`[API] JSON parsed in ${parseTime}ms`);

        if (result.success) {
            const updateStart = Date.now();
            updateDashboard(result.data);
            const updateTime = Date.now() - updateStart;
            console.log(`[API] Dashboard updated in ${updateTime}ms`);
            console.log(`[API] Total: ${Date.now() - fetchStart}ms`);
        } else {
            console.error('[API] Error loading dashboard data:', result.error);
        }
    } catch (error) {
        console.error('[API] Error fetching dashboard data:', error);
    }
}

function updateDashboard(data) {
    if (data.recent_alerts) {
        updateAlertFeed(data.recent_alerts);
    }

    if (data.alert_stats) {
        updateAlertStats(data.alert_stats);
    }

    if (data.traffic_history) {
        updateTrafficChart(data.traffic_history);
    }

    if (data.top_talkers) {
        updateTopTalkers(data.top_talkers);
    }

    // Update gauges with current metrics
    if (data.current_metrics) {
        updateMetrics(data.current_metrics);
    }
}

// ==================== Charts ====================

function initCharts() {
    // Traffic Chart
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Inbound (MB)',
                    data: [],
                    borderColor: '#28a745',
                    backgroundColor: 'rgba(40, 167, 69, 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Outbound (MB)',
                    data: [],
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#ddd' }
                }
            },
            scales: {
                x: {
                    ticks: { color: '#aaa' },
                    grid: { color: '#333' }
                },
                y: {
                    ticks: { color: '#aaa' },
                    grid: { color: '#333' }
                }
            }
        }
    });

    // Alert Pie Chart
    const pieCtx = document.getElementById('alertPieChart').getContext('2d');
    alertPieChart = new Chart(pieCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#dc3545', // CRITICAL
                    '#fd7e14', // HIGH
                    '#ffc107', // MEDIUM
                    '#17a2b8', // LOW
                    '#6c757d'  // INFO
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#ddd' }
                }
            }
        }
    });

    // Initialize gauges
    initGauges();
}

function initGauges() {
    const gaugeOptions = {
        type: 'doughnut',
        options: {
            responsive: true,
            maintainAspectRatio: false,
            circumference: 180,
            rotation: 270,
            cutout: '75%',
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false }
            }
        }
    };

    // Packets Gauge
    packetsGauge = new Chart(document.getElementById('packetsGauge').getContext('2d'), {
        ...gaugeOptions,
        data: {
            datasets: [{
                data: [0, 100],
                backgroundColor: ['#28a745', '#333'],
                borderWidth: 0
            }]
        }
    });

    // Alerts Gauge
    alertsGauge = new Chart(document.getElementById('alertsGauge').getContext('2d'), {
        ...gaugeOptions,
        data: {
            datasets: [{
                data: [0, 100],
                backgroundColor: ['#ffc107', '#333'],
                borderWidth: 0
            }]
        }
    });

    // CPU Gauge
    cpuGauge = new Chart(document.getElementById('cpuGauge').getContext('2d'), {
        ...gaugeOptions,
        data: {
            datasets: [{
                data: [0, 100],
                backgroundColor: ['#17a2b8', '#333'],
                borderWidth: 0
            }]
        }
    });

    // Memory Gauge
    memoryGauge = new Chart(document.getElementById('memoryGauge').getContext('2d'), {
        ...gaugeOptions,
        data: {
            datasets: [{
                data: [0, 100],
                backgroundColor: ['#fd7e14', '#333'],
                borderWidth: 0
            }]
        }
    });

    // Disk Usage Gauge
    diskGauge = new Chart(document.getElementById('diskGauge').getContext('2d'), {
        ...gaugeOptions,
        data: {
            datasets: [{
                data: [0, 100],
                backgroundColor: ['#6f42c1', '#333'],
                borderWidth: 0
            }]
        }
    });
}

function updateGauge(chart, value, max = 100) {
    const percentage = Math.min((value / max) * 100, 100);
    chart.data.datasets[0].data = [percentage, 100 - percentage];
    chart.update('none'); // Update without animation
}

function updateTrafficChart(history) {
    if (!history || history.length === 0) return;

    // Take last 24 data points (1 per hour if sampling every hour)
    const data = history.slice(-24);

    const labels = data.map(item => {
        const date = new Date(item.timestamp);
        return date.getHours() + ':00';
    });

    const inboundData = data.map(item => (item.inbound_bytes / (1024 * 1024)).toFixed(2));
    const outboundData = data.map(item => (item.outbound_bytes / (1024 * 1024)).toFixed(2));

    trafficChart.data.labels = labels;
    trafficChart.data.datasets[0].data = inboundData;
    trafficChart.data.datasets[1].data = outboundData;
    trafficChart.update();
}

// ==================== Alerts ====================

function groupAlerts(alerts) {
    /**
     * Group consecutive similar alerts by threat_type and source_ip
     */
    if (!alerts || alerts.length === 0) return [];

    const groups = [];
    let currentGroup = null;

    alerts.forEach(alert => {
        const key = `${alert.threat_type}_${alert.source_ip || 'unknown'}`;

        if (!currentGroup || currentGroup.key !== key) {
            // Start new group
            currentGroup = {
                key: key,
                threat_type: alert.threat_type,
                source_ip: alert.source_ip,
                destination_ip: alert.destination_ip,
                severity: alert.severity,
                count: 1,
                first_seen: alert.timestamp,
                last_seen: alert.timestamp,
                alerts: [alert]
            };
            groups.push(currentGroup);
        } else {
            // Add to existing group
            currentGroup.count++;
            currentGroup.last_seen = alert.timestamp;
            currentGroup.alerts.push(alert);
        }
    });

    return groups;
}

function updateAlertFeed(alerts) {
    const feed = document.getElementById('alert-feed');
    const alertCount = document.getElementById('alert-count');

    if (!alerts || alerts.length === 0) {
        feed.innerHTML = '<div class="text-center text-muted p-4">No alerts</div>';
        alertCount.textContent = '0';
        return;
    }

    alertCount.textContent = alerts.length;

    // Group similar alerts
    const groups = groupAlerts(alerts);

    // Clear feed
    feed.innerHTML = '';

    // Add grouped alerts
    groups.forEach(group => addGroupedAlertToFeed(group));
}

function addGroupedAlertToFeed(group) {
    const feed = document.getElementById('alert-feed');

    const alertDiv = document.createElement('div');
    alertDiv.className = `alert-item ${group.severity}`;
    alertDiv.style.cursor = 'pointer';

    const timestamp = new Date(group.last_seen).toLocaleString('nl-NL');
    const countBadge = group.count > 1 ?
        `<span class="badge bg-warning text-dark ms-2">${group.count}x</span>` : '';

    let metaInfo = '';
    if (group.source_ip) {
        metaInfo += `<i class="bi bi-arrow-right-circle"></i> ${group.source_ip}`;
    }
    if (group.destination_ip) {
        metaInfo += ` → ${group.destination_ip}`;
    }

    // Use first alert's description
    const description = group.alerts[0].description;

    alertDiv.innerHTML = `
        <div class="d-flex justify-content-between align-items-start">
            <div class="flex-grow-1">
                <div>
                    <span class="alert-severity ${group.severity}">${group.severity}</span>
                    <strong>${group.threat_type}</strong>${countBadge}
                    <span class="alert-timestamp">${timestamp}</span>
                </div>
                <div class="alert-description">${description}</div>
                ${metaInfo ? `<div class="alert-meta">${metaInfo}</div>` : ''}
            </div>
            ${group.count > 1 ? '<i class="bi bi-chevron-right ms-2"></i>' : ''}
        </div>
    `;

    // Add click handler to show modal
    alertDiv.addEventListener('click', () => showAlertDetails(group));

    feed.appendChild(alertDiv);
}

function addAlertToFeed(alert, prepend = false) {
    // Create a group with single alert for new real-time alerts
    const group = {
        threat_type: alert.threat_type,
        source_ip: alert.source_ip,
        destination_ip: alert.destination_ip,
        severity: alert.severity,
        count: 1,
        last_seen: alert.timestamp,
        alerts: [alert]
    };

    const feed = document.getElementById('alert-feed');

    const alertDiv = document.createElement('div');
    alertDiv.className = `alert-item ${alert.severity}`;
    if (prepend) alertDiv.classList.add('new');
    alertDiv.style.cursor = 'pointer';

    const timestamp = new Date(alert.timestamp).toLocaleString('nl-NL');

    let metaInfo = '';
    if (alert.source_ip) {
        metaInfo += `<i class="bi bi-arrow-right-circle"></i> ${alert.source_ip}`;
    }
    if (alert.destination_ip) {
        metaInfo += ` → ${alert.destination_ip}`;
    }

    alertDiv.innerHTML = `
        <div class="d-flex justify-content-between align-items-start">
            <div class="flex-grow-1">
                <div>
                    <span class="alert-severity ${alert.severity}">${alert.severity}</span>
                    <strong>${alert.threat_type}</strong>
                    <span class="alert-timestamp">${timestamp}</span>
                </div>
                <div class="alert-description">${alert.description}</div>
                ${metaInfo ? `<div class="alert-meta">${metaInfo}</div>` : ''}
            </div>
        </div>
    `;

    // Add click handler to show modal
    alertDiv.addEventListener('click', () => showAlertDetails(group));

    if (prepend) {
        feed.prepend(alertDiv);
    } else {
        feed.appendChild(alertDiv);
    }

    // Remove 'new' class after animation
    if (prepend) {
        setTimeout(() => alertDiv.classList.remove('new'), 300);
    }
}

function showAlertDetails(group) {
    const modalTitle = document.getElementById('alertDetailsModalLabel');
    const modalBody = document.getElementById('alertDetailsBody');

    // Update modal title
    const countText = group.count > 1 ? ` (${group.count} occurrences)` : '';
    modalTitle.innerHTML = `
        <i class="bi bi-info-circle"></i>
        <span class="alert-severity ${group.severity}">${group.severity}</span>
        ${group.threat_type}${countText}
    `;

    // Build alert details
    let detailsHTML = '';

    if (group.count === 1) {
        // Single alert - show full details
        const alert = group.alerts[0];
        detailsHTML = `
            <div class="alert-detail-section">
                <h6><i class="bi bi-clock"></i> Timestamp</h6>
                <p>${new Date(alert.timestamp).toLocaleString('nl-NL')}</p>
            </div>

            <div class="alert-detail-section">
                <h6><i class="bi bi-shield-exclamation"></i> Threat Type</h6>
                <p>${alert.threat_type}</p>
            </div>

            ${alert.source_ip ? `
            <div class="alert-detail-section">
                <h6><i class="bi bi-hdd-network"></i> Source IP</h6>
                <p>${alert.source_ip}</p>
            </div>
            ` : ''}

            ${alert.destination_ip ? `
            <div class="alert-detail-section">
                <h6><i class="bi bi-hdd-network-fill"></i> Destination IP</h6>
                <p>${alert.destination_ip}</p>
            </div>
            ` : ''}

            <div class="alert-detail-section">
                <h6><i class="bi bi-file-text"></i> Description</h6>
                <p>${alert.description}</p>
            </div>

            ${alert.metadata ? `
            <div class="alert-detail-section">
                <h6><i class="bi bi-code-square"></i> Additional Information</h6>
                <pre class="bg-secondary p-2 rounded"><code>${alert.metadata}</code></pre>
            </div>
            ` : ''}
        `;
    } else {
        // Multiple alerts - show summary and list
        detailsHTML = `
            <div class="alert-detail-section">
                <h6><i class="bi bi-calendar-range"></i> Time Range</h6>
                <p>
                    First seen: ${new Date(group.first_seen).toLocaleString('nl-NL')}<br>
                    Last seen: ${new Date(group.last_seen).toLocaleString('nl-NL')}
                </p>
            </div>

            ${group.source_ip ? `
            <div class="alert-detail-section">
                <h6><i class="bi bi-hdd-network"></i> Source IP</h6>
                <p>${group.source_ip}</p>
            </div>
            ` : ''}

            ${group.destination_ip ? `
            <div class="alert-detail-section">
                <h6><i class="bi bi-hdd-network-fill"></i> Destination IP</h6>
                <p>${group.destination_ip}</p>
            </div>
            ` : ''}

            <div class="alert-detail-section">
                <h6><i class="bi bi-list-ul"></i> All Occurrences (${group.count})</h6>
                <div class="list-group">
        `;

        group.alerts.forEach((alert, index) => {
            detailsHTML += `
                <div class="list-group-item bg-secondary text-light mb-2">
                    <div class="d-flex justify-content-between">
                        <strong>#${index + 1}</strong>
                        <small>${new Date(alert.timestamp).toLocaleString('nl-NL')}</small>
                    </div>
                    <p class="mb-1 mt-2">${alert.description}</p>
                    ${alert.metadata ? `<small class="text-muted">${alert.metadata}</small>` : ''}
                </div>
            `;
        });

        detailsHTML += `
                </div>
            </div>
        `;
    }

    modalBody.innerHTML = detailsHTML;

    // Show the modal
    const modal = new bootstrap.Modal(document.getElementById('alertDetailsModal'));
    modal.show();
}

function updateAlertStats(stats) {
    // Update alert pie chart
    if (stats.by_severity) {
        const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
        const data = severities.map(sev => stats.by_severity[sev] || 0);

        alertPieChart.data.labels = severities;
        alertPieChart.data.datasets[0].data = data;
        alertPieChart.update();
    }

    // Update threat types list
    if (stats.by_type) {
        const list = document.getElementById('threat-types-list');
        list.innerHTML = '';

        const sortedTypes = Object.entries(stats.by_type)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10);

        if (sortedTypes.length === 0) {
            list.innerHTML = '<div class="list-group-item bg-dark text-muted text-center">No threats detected</div>';
            return;
        }

        sortedTypes.forEach(([type, count]) => {
            const threatInfo = THREAT_INFO[type] || {
                name: type.replace(/_/g, ' '),
                description: 'Onbekend threat type',
                impact: 'Zie alert details voor meer informatie',
                icon: 'bi-question-circle',
                color: '#6c757d'
            };

            const item = document.createElement('div');
            item.className = 'list-group-item bg-dark d-flex justify-content-between align-items-center threat-type-item';
            item.style.cursor = 'pointer';
            item.style.borderLeft = `3px solid ${threatInfo.color}`;

            // Add tooltip
            item.setAttribute('data-bs-toggle', 'tooltip');
            item.setAttribute('data-bs-placement', 'left');
            item.setAttribute('data-bs-html', 'true');
            item.setAttribute('title', `
                <div class="text-start">
                    <strong>${threatInfo.name}</strong><br/>
                    <small>${threatInfo.description}</small><br/>
                    <br/>
                    <strong>Impact:</strong><br/>
                    <small>${threatInfo.impact}</small>
                </div>
            `);

            item.innerHTML = `
                <span>
                    <i class="bi ${threatInfo.icon} me-2"></i>
                    ${threatInfo.name}
                </span>
                <span class="badge bg-danger rounded-pill">${count}</span>
            `;

            // Add click handler to show threat details
            item.addEventListener('click', () => showThreatTypeDetails(type));

            list.appendChild(item);
        });

        // Initialize Bootstrap tooltips
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        const tooltips = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl, {
                html: true,
                trigger: 'hover'
            });
        });

        // Hide tooltips on scroll to prevent sticky tooltips
        window.addEventListener('scroll', function() {
            tooltips.forEach(tooltip => {
                if (tooltip && tooltip.hide) {
                    tooltip.hide();
                }
            });
        }, true); // Use capture phase to catch all scroll events
    }
}

// ==================== Threat Type Details ====================

// State for threat details
let currentThreatData = {
    threatType: null,
    threatInfo: null,
    allAlerts: [],
    displayedAlerts: 0,
    alertsPerPage: 20,
    totalAlerts: 0  // Track total number of alerts available
};

async function showThreatTypeDetails(threatType) {
    console.log(`[THREAT DETAILS] Loading details for: ${threatType}`);

    // Get threat info
    const threatInfo = THREAT_INFO[threatType] || {
        name: threatType.replace(/_/g, ' '),
        description: 'Onbekend threat type',
        impact: 'Zie alert details voor meer informatie',
        icon: 'bi-question-circle',
        color: '#6c757d'
    };

    // Store in state
    currentThreatData.threatType = threatType;
    currentThreatData.threatInfo = threatInfo;
    currentThreatData.displayedAlerts = 0;

    // Update modal title
    const modalTitle = document.getElementById('threatDetailsModalLabel');
    modalTitle.innerHTML = `
        <i class="bi ${threatInfo.icon}"></i>
        ${threatInfo.name}
    `;

    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('threatDetailsModal'));
    modal.show();

    // Show loading
    document.getElementById('threatDetailsLoading').style.display = 'block';
    document.getElementById('threatDetailsContent').style.display = 'none';

    try {
        // Fetch threat details - only load first 20 alerts for speed
        const response = await fetch(`/api/threat-details/${threatType}?hours=24&limit=20`);
        const result = await response.json();

        if (result.success) {
            console.log(`[THREAT DETAILS] Received data:`, result.data);

            // Store all alerts and total count
            currentThreatData.allAlerts = result.data.alerts || [];
            currentThreatData.totalAlerts = (result.data.statistics && result.data.statistics.total_count) || result.data.alerts.length;

            displayThreatDetails(result.data, threatInfo);
        } else {
            console.error('[THREAT DETAILS] Error:', result.error);
            showThreatDetailsError(result.error);
        }
    } catch (error) {
        console.error('[THREAT DETAILS] Fetch error:', error);
        showThreatDetailsError(error.message);
    }
}

async function loadMoreAlerts() {
    console.log('[THREAT DETAILS] Loading more alerts...');

    const loadMoreBtn = document.getElementById('loadMoreAlertsBtn');
    const btnText = loadMoreBtn.querySelector('.btn-text');
    const btnSpinner = loadMoreBtn.querySelector('.btn-spinner');

    // Show loading state
    loadMoreBtn.disabled = true;
    btnText.style.display = 'none';
    btnSpinner.style.display = 'inline-block';

    try {
        // Calculate new limit
        const newLimit = currentThreatData.displayedAlerts + currentThreatData.alertsPerPage + 20;

        // Fetch more alerts
        const response = await fetch(`/api/threat-details/${currentThreatData.threatType}?hours=24&limit=${newLimit}`);
        const result = await response.json();

        if (result.success) {
            currentThreatData.allAlerts = result.data.alerts || [];
            currentThreatData.totalAlerts = (result.data.statistics && result.data.statistics.total_count) || result.data.alerts.length;

            // Render alerts starting from where we left off
            renderAlertsIncremental();
        }
    } catch (error) {
        console.error('[THREAT DETAILS] Error loading more alerts:', error);
    } finally {
        // Restore button state
        loadMoreBtn.disabled = false;
        btnText.style.display = 'inline';
        btnSpinner.style.display = 'none';
    }
}

function displayThreatDetails(data, threatInfo) {
    // Hide loading, show content
    document.getElementById('threatDetailsLoading').style.display = 'none';
    document.getElementById('threatDetailsContent').style.display = 'block';

    const stats = data.statistics || {};

    // Populate statistics cards
    const statsRow = document.getElementById('threatStatsRow');
    statsRow.innerHTML = `
        <div class="col-md-3">
            <div class="card bg-secondary">
                <div class="card-body text-center">
                    <h6 class="text-muted">Total Alerts</h6>
                    <h3 class="text-danger">${stats.total_count || 0}</h3>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-secondary">
                <div class="card-body text-center">
                    <h6 class="text-muted">Unique Sources</h6>
                    <h3 class="text-warning">${stats.unique_sources || 0}</h3>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-secondary">
                <div class="card-body text-center">
                    <h6 class="text-muted">Unique Targets</h6>
                    <h3 class="text-info">${stats.unique_targets || 0}</h3>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card bg-secondary">
                <div class="card-body text-center">
                    <h6 class="text-muted">First Seen</h6>
                    <p class="mb-0"><small>${stats.first_seen ? new Date(stats.first_seen).toLocaleString('nl-NL') : 'N/A'}</small></p>
                </div>
            </div>
        </div>
    `;

    // Populate overview
    const overviewContent = document.getElementById('threatOverviewContent');

    // Extract threat-specific information
    let threatSpecificInfo = '';

    // For PORT_SCAN: collect all scanned ports
    if (data.threat_type === 'PORT_SCAN') {
        const allPorts = new Set();
        const portFrequency = {};

        data.alerts.forEach(alert => {
            if (alert.metadata_parsed && alert.metadata_parsed.ports) {
                alert.metadata_parsed.ports.forEach(port => {
                    allPorts.add(port);
                    portFrequency[port] = (portFrequency[port] || 0) + 1;
                });
            }
        });

        if (allPorts.size > 0) {
            // Sort ports numerically
            const sortedPorts = Array.from(allPorts).sort((a, b) => a - b);

            // Get most scanned ports
            const topPorts = Object.entries(portFrequency)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([port, count]) => ({ port: parseInt(port), count }));

            threatSpecificInfo = `
                <div class="card bg-secondary mt-3">
                    <div class="card-body">
                        <h6><i class="bi bi-hdd-network"></i> Gescande Poorten</h6>
                        <p><strong>Totaal aantal unieke poorten:</strong> ${allPorts.size}</p>

                        <div class="mt-3">
                            <strong>Top 10 meest gescande poorten:</strong>
                            <div class="mt-2">
                                ${topPorts.map(p => `
                                    <div class="d-inline-block me-2 mb-2">
                                        <span class="badge bg-danger" style="font-size: 0.9rem;">
                                            Port ${p.port}
                                            <span class="badge bg-dark ms-1">${p.count}x</span>
                                        </span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>

                        ${sortedPorts.length <= 50 ? `
                            <div class="mt-3">
                                <strong>Alle gescande poorten:</strong>
                                <div class="mt-2" style="max-height: 200px; overflow-y: auto;">
                                    ${sortedPorts.map(port =>
                                        `<span class="badge bg-secondary me-1 mb-1">${port}</span>`
                                    ).join('')}
                                </div>
                            </div>
                        ` : `
                            <div class="mt-3">
                                <p class="text-muted mb-0">
                                    <small>Eerste 50 poorten: ${sortedPorts.slice(0, 50).join(', ')}...</small>
                                </p>
                            </div>
                        `}
                    </div>
                </div>
            `;
        }
    }

    // For BEACONING: show beacon patterns
    if (data.threat_type === 'BEACONING_DETECTED') {
        const intervals = new Set();

        data.alerts.forEach(alert => {
            if (alert.metadata_parsed && alert.metadata_parsed.interval) {
                intervals.add(alert.metadata_parsed.interval);
            }
        });

        if (intervals.size > 0) {
            threatSpecificInfo = `
                <div class="card bg-secondary mt-3">
                    <div class="card-body">
                        <h6><i class="bi bi-broadcast"></i> Beacon Patronen</h6>
                        <p><strong>Gedetecteerde intervals:</strong></p>
                        <div class="mt-2">
                            ${Array.from(intervals).sort((a, b) => a - b).map(interval =>
                                `<span class="badge bg-warning text-dark me-2 mb-2" style="font-size: 0.9rem;">${interval}s</span>`
                            ).join('')}
                        </div>
                    </div>
                </div>
            `;
        }
    }

    overviewContent.innerHTML = `
        <div class="alert alert-info">
            <h6><i class="bi bi-info-circle"></i> Beschrijving</h6>
            <p class="mb-2">${threatInfo.description}</p>
            <h6 class="mt-3"><i class="bi bi-exclamation-triangle"></i> Impact</h6>
            <p class="mb-0">${threatInfo.impact}</p>
        </div>

        <h6 class="mt-3">Recente Activiteit</h6>
        <div class="row">
            <div class="col-md-6">
                <p><strong>Eerste detectie:</strong> ${stats.first_seen ? new Date(stats.first_seen).toLocaleString('nl-NL') : 'N/A'}</p>
            </div>
            <div class="col-md-6">
                <p><strong>Laatste detectie:</strong> ${stats.last_seen ? new Date(stats.last_seen).toLocaleString('nl-NL') : 'N/A'}</p>
            </div>
        </div>

        ${threatSpecificInfo}
    `;

    // Populate top sources table
    const sourcesTable = document.getElementById('threatSourcesTable');
    if (data.top_sources && data.top_sources.length > 0) {
        sourcesTable.innerHTML = data.top_sources.map(source => `
            <tr>
                <td><code>${source.ip}</code></td>
                <td>${source.hostname || '<span class="text-muted">N/A</span>'}</td>
                <td>${source.country || '<span class="text-muted">Unknown</span>'}</td>
                <td><span class="badge bg-danger">${source.count}</span></td>
            </tr>
        `).join('');
    } else {
        sourcesTable.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No source IPs</td></tr>';
    }

    // Populate top targets table
    const targetsTable = document.getElementById('threatTargetsTable');
    if (data.top_targets && data.top_targets.length > 0) {
        targetsTable.innerHTML = data.top_targets.map(target => `
            <tr>
                <td><code>${target.ip}</code></td>
                <td>${target.hostname || '<span class="text-muted">N/A</span>'}</td>
                <td>${target.country || '<span class="text-muted">Unknown</span>'}</td>
                <td><span class="badge bg-danger">${target.count}</span></td>
            </tr>
        `).join('');
    } else {
        targetsTable.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No target IPs</td></tr>';
    }

    // Populate all alerts - initial load with first batch only
    renderAlertsList(data);
}

function renderAlertsList(data) {
    const alertsContent = document.getElementById('threatAlertsContent');

    if (!data.alerts || data.alerts.length === 0) {
        alertsContent.innerHTML = '<div class="text-center text-muted p-4">No alerts found</div>';
        return;
    }

    // Show first batch of alerts
    const alertsToShow = data.alerts.slice(0, currentThreatData.alertsPerPage);
    currentThreatData.displayedAlerts = alertsToShow.length;

    const alertsHTML = alertsToShow.map((alert, index) => {
        return renderAlertCard(alert, data.threat_type);
    }).join('');

    // Use totalAlerts from statistics instead of data.alerts.length
    const totalCount = currentThreatData.totalAlerts;
    const hasMore = totalCount > currentThreatData.displayedAlerts;
    const remainingCount = totalCount - currentThreatData.displayedAlerts;

    alertsContent.innerHTML = `
        <div class="alert-list" id="alertListContainer">
            ${alertsHTML}
        </div>
        ${hasMore ? `
            <div class="text-center mt-3">
                <button class="btn btn-outline-info" id="loadMoreAlertsBtn" onclick="loadMoreAlerts()">
                    <span class="btn-text">
                        <i class="bi bi-arrow-down-circle"></i>
                        Laad ${Math.min(20, remainingCount)} meer alerts (${remainingCount} remaining)
                    </span>
                    <span class="btn-spinner" style="display: none;">
                        <span class="spinner-border spinner-border-sm" role="status"></span>
                        Loading...
                    </span>
                </button>
            </div>
        ` : `
            <div class="text-center mt-3" style="color: #aaa;">
                <small>Alle ${totalCount} alerts getoond</small>
            </div>
        `}
    `;
}

function renderAlertsIncremental() {
    const alertListContainer = document.getElementById('alertListContainer');
    if (!alertListContainer) return;

    const data = { alerts: currentThreatData.allAlerts, threat_type: currentThreatData.threatType };

    // Calculate which alerts to add
    const startIndex = currentThreatData.displayedAlerts;
    const endIndex = Math.min(startIndex + currentThreatData.alertsPerPage, data.alerts.length);
    const newAlerts = data.alerts.slice(startIndex, endIndex);

    // Append new alerts
    const newAlertsHTML = newAlerts.map(alert => renderAlertCard(alert, data.threat_type)).join('');
    alertListContainer.insertAdjacentHTML('beforeend', newAlertsHTML);

    // Update displayed count
    currentThreatData.displayedAlerts = endIndex;

    // Update or hide the button
    const loadMoreBtn = document.getElementById('loadMoreAlertsBtn');
    const totalCount = currentThreatData.totalAlerts;
    const hasMore = totalCount > currentThreatData.displayedAlerts;
    const remainingCount = totalCount - currentThreatData.displayedAlerts;

    if (hasMore && loadMoreBtn) {
        const btnText = loadMoreBtn.querySelector('.btn-text');
        btnText.innerHTML = `
            <i class="bi bi-arrow-down-circle"></i>
            Laad ${Math.min(20, remainingCount)} meer alerts (${remainingCount} remaining)
        `;
    } else if (loadMoreBtn) {
        loadMoreBtn.parentElement.innerHTML = `
            <div class="text-center mt-3" style="color: #aaa;">
                <small>Alle ${totalCount} alerts getoond</small>
            </div>
        `;
    }
}

function renderAlertCard(alert, threatType) {
    const metadata = alert.metadata_parsed || {};
    let extraInfo = '';

    // Special handling for PORT_SCAN
    if (threatType === 'PORT_SCAN' && metadata.ports) {
        extraInfo = `
            <div class="mt-2">
                <strong>Gescande poorten:</strong>
                <div class="mt-1">
                    ${metadata.ports.slice(0, 20).map(port =>
                        `<span class="badge bg-secondary me-1">${port}</span>`
                    ).join('')}
                    ${metadata.ports.length > 20 ?
                        `<span class="badge bg-info">+${metadata.ports.length - 20} more</span>` : ''}
                </div>
            </div>
        `;
    }

    // Special handling for BEACONING_DETECTED
    if (threatType === 'BEACONING_DETECTED' && metadata.interval) {
        extraInfo = `
            <div class="mt-2">
                <strong>Beacon interval:</strong> ${metadata.interval}s
            </div>
        `;
    }

    return `
        <div class="card bg-secondary mb-2">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <span class="badge bg-${alert.severity === 'CRITICAL' ? 'danger' : alert.severity === 'HIGH' ? 'warning' : 'info'}">${alert.severity}</span>
                        <small class="text-muted ms-2">${new Date(alert.timestamp).toLocaleString('nl-NL')}</small>
                    </div>
                    <div>
                        ${alert.acknowledged ? '<span class="badge bg-success">Acknowledged</span>' : ''}
                    </div>
                </div>
                <p class="mb-1 mt-2">${alert.description}</p>
                ${alert.source_ip ? `
                    <div class="mt-2">
                        <i class="bi bi-arrow-right-circle text-danger"></i>
                        <code>${alert.source_ip}</code>
                        ${alert.source_hostname ? `<small class="text-muted">(${alert.source_hostname})</small>` : ''}
                        ${alert.source_country ? `<small class="text-muted"> - ${alert.source_country}</small>` : ''}
                    </div>
                ` : ''}
                ${alert.destination_ip ? `
                    <div class="mt-1">
                        <i class="bi bi-arrow-down-circle text-info"></i>
                        <code>${alert.destination_ip}</code>
                        ${alert.destination_hostname ? `<small class="text-muted">(${alert.destination_hostname})</small>` : ''}
                        ${alert.destination_country ? `<small class="text-muted"> - ${alert.destination_country}</small>` : ''}
                    </div>
                ` : ''}
                ${extraInfo}
            </div>
        </div>
    `;
}

function showThreatDetailsError(error) {
    document.getElementById('threatDetailsLoading').style.display = 'none';
    document.getElementById('threatDetailsContent').style.display = 'block';

    const overviewContent = document.getElementById('threatOverviewContent');
    overviewContent.innerHTML = `
        <div class="alert alert-danger">
            <h6><i class="bi bi-exclamation-triangle"></i> Error Loading Threat Details</h6>
            <p class="mb-0">${error}</p>
        </div>
    `;
}

// ==================== Top Talkers ====================

function updateTopTalkers(talkers) {
    const tbody = document.getElementById('top-talkers-table');

    if (!talkers || talkers.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No data</td></tr>';
        return;
    }

    tbody.innerHTML = '';

    talkers.forEach(talker => {
        const row = document.createElement('tr');

        const bytes = talker.bytes || 0;
        const mb = (bytes / (1024 * 1024)).toFixed(2);

        const direction = talker.direction || 'unknown';
        const directionBadge = direction === 'outbound' ?
            '<span class="badge badge-direction outbound">OUT</span>' :
            '<span class="badge badge-direction inbound">IN</span>';

        // Support both 'ip' and 'ip_address' for backwards compatibility
        const ipAddress = talker.ip || talker.ip_address || 'unknown';

        row.innerHTML = `
            <td>
                <small>${ipAddress}</small>
                ${talker.hostname && talker.hostname !== ipAddress ?
                  `<br><small class="text-muted">${talker.hostname}</small>` : ''}
            </td>
            <td>${mb} MB</td>
            <td>${directionBadge}</td>
        `;

        tbody.appendChild(row);
    });
}

// ==================== Metrics Update ====================

function updateMetrics(metrics) {
    if (!metrics) return;

    // Update gauges
    if (metrics.traffic) {
        const pps = metrics.traffic.packets_per_second || 0;
        document.getElementById('packets-value').textContent = pps.toFixed(0);
        updateGauge(packetsGauge, pps, 10000); // Max 10k pps

        const apm = metrics.traffic.alerts_per_minute || 0;
        document.getElementById('alerts-value').textContent = apm;
        updateGauge(alertsGauge, apm, 100); // Max 100 alerts/min
    }

    if (metrics.system) {
        const cpu = metrics.system.cpu_percent || 0;
        document.getElementById('cpu-value').textContent = cpu.toFixed(1) + '%';
        updateGauge(cpuGauge, cpu, 100);

        const memory = metrics.system.memory_percent || 0;
        document.getElementById('memory-value').textContent = memory.toFixed(1) + '%';
        updateGauge(memoryGauge, memory, 100);
    }

    // Update top talkers
    if (metrics.top_talkers) {
        updateTopTalkers(metrics.top_talkers);
    }
}

// ==================== Utility Functions ====================

function updateClock() {
    const now = new Date();
    document.getElementById('current-time').textContent = now.toLocaleString('nl-NL');
}

function playAlertSound(severity) {
    // Optional: play sound for critical/high alerts
    if (severity === 'CRITICAL' || severity === 'HIGH') {
        // Beep sound using Web Audio API
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();

            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);

            oscillator.frequency.value = severity === 'CRITICAL' ? 800 : 600;
            oscillator.type = 'sine';

            gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.3);

            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.3);
        } catch (error) {
            console.error('Error playing alert sound:', error);
        }
    }
}

// ==================== Sensors ====================

async function loadSensors() {
    try {
        const response = await fetch('/api/sensors/');
        const result = await response.json();

        if (result.success) {
            updateSensorsTable(result.data);
        }
    } catch (error) {
        console.error('[SENSORS] Error loading sensors:', error);
    }
}

function updateSensorsTable(sensors) {
    const tbody = document.getElementById('sensors-table');
    const countBadge = document.getElementById('sensors-count');
    const onlineBadge = document.getElementById('sensors-online');

    if (!sensors || sensors.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted">No sensors registered</td></tr>';
        countBadge.textContent = '0';
        onlineBadge.textContent = '0';
        return;
    }

    // Count online sensors
    const online = sensors.filter(s => s.computed_status === 'online').length;

    countBadge.textContent = sensors.length;
    onlineBadge.textContent = online;

    tbody.innerHTML = '';

    sensors.forEach(sensor => {
        const row = document.createElement('tr');

        // Status badge
        let statusBadge = '';
        let statusClass = '';
        switch(sensor.computed_status) {
            case 'online':
                statusBadge = '<span class="badge bg-success"><i class="bi bi-circle-fill"></i> Online</span>';
                break;
            case 'warning':
                statusBadge = '<span class="badge bg-warning text-dark"><i class="bi bi-exclamation-triangle"></i> Warning</span>';
                break;
            default:
                statusBadge = '<span class="badge bg-danger"><i class="bi bi-x-circle"></i> Offline</span>';
        }

        // Format last seen
        let lastSeen = 'Never';
        if (sensor.last_seen) {
            const diff = Date.now() - new Date(sensor.last_seen);
            const seconds = Math.floor(diff / 1000);
            if (seconds < 60) {
                lastSeen = `${seconds}s ago`;
            } else if (seconds < 3600) {
                lastSeen = `${Math.floor(seconds / 60)}m ago`;
            } else if (seconds < 86400) {
                lastSeen = `${Math.floor(seconds / 3600)}h ago`;
            } else {
                lastSeen = new Date(sensor.last_seen).toLocaleString('nl-NL');
            }
        }

        // CPU and RAM with color coding
        const cpuClass = sensor.cpu_percent > 80 ? 'text-danger' : sensor.cpu_percent > 60 ? 'text-warning' : 'text-success';
        const ramClass = sensor.memory_percent > 80 ? 'text-danger' : sensor.memory_percent > 60 ? 'text-warning' : 'text-success';

        // Bandwidth with color coding (>80 Mbps = warning, >200 = danger)
        const bwClass = sensor.bandwidth_mbps > 200 ? 'text-danger' : sensor.bandwidth_mbps > 80 ? 'text-warning' : 'text-success';

        row.innerHTML = `
            <td>${statusBadge}</td>
            <td>
                <strong>${sensor.hostname}</strong><br>
                <small class="text-muted">${sensor.sensor_id}</small>
            </td>
            <td>
                ${sensor.location || '<span class="text-muted">-</span>'}<br>
                <small class="text-muted"><i class="bi bi-hdd-network"></i> ${sensor.ip_address || 'No IP'}</small>
            </td>
            <td class="${cpuClass}">
                ${sensor.cpu_percent != null ? sensor.cpu_percent.toFixed(1) + '%' : '<span class="text-muted">-</span>'}
            </td>
            <td class="${ramClass}">
                ${sensor.memory_percent != null ? sensor.memory_percent.toFixed(1) + '%' : '<span class="text-muted">-</span>'}
            </td>
            <td class="${bwClass}">
                ${sensor.bandwidth_mbps != null ? sensor.bandwidth_mbps.toFixed(1) + ' Mbps' : '<span class="text-muted">-</span>'}
            </td>
            <td>
                ${sensor.packets_captured != null ? sensor.packets_captured.toLocaleString() : '<span class="text-muted">-</span>'}
            </td>
            <td>
                <span class="badge ${sensor.alerts_24h > 0 ? 'bg-danger' : 'bg-secondary'}">
                    ${sensor.alerts_24h || 0}
                </span>
            </td>
            <td><small>${lastSeen}</small></td>
            <td>
                <div class="btn-group btn-group-sm" role="group">
                    <button class="btn btn-outline-primary update-sensor-btn"
                            data-sensor-id="${sensor.sensor_id}"
                            data-sensor-name="${sensor.hostname}"
                            title="Update sensor software">
                        <i class="bi bi-arrow-clockwise"></i>
                    </button>
                    <button class="btn btn-outline-warning reboot-sensor-btn"
                            data-sensor-id="${sensor.sensor_id}"
                            data-sensor-name="${sensor.hostname}"
                            title="Reboot sensor">
                        <i class="bi bi-power"></i>
                    </button>
                    <button class="btn btn-outline-info edit-settings-btn"
                            data-sensor-id="${sensor.sensor_id}"
                            data-sensor-name="${sensor.hostname}"
                            data-sensor-location="${sensor.location || ''}"
                            title="Edit sensor settings">
                        <i class="bi bi-sliders"></i>
                    </button>
                    <button class="btn btn-outline-danger delete-sensor-btn"
                            data-sensor-id="${sensor.sensor_id}"
                            data-sensor-name="${sensor.hostname}"
                            title="Delete sensor">
                        <i class="bi bi-trash"></i>
                    </button>
                </div>
            </td>
        `;

        tbody.appendChild(row);
    });

    // Add event listeners to action buttons
    document.querySelectorAll('.update-sensor-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const sensorId = this.getAttribute('data-sensor-id');
            const sensorName = this.getAttribute('data-sensor-name');
            updateSensor(sensorId, sensorName);
        });
    });

    document.querySelectorAll('.reboot-sensor-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const sensorId = this.getAttribute('data-sensor-id');
            const sensorName = this.getAttribute('data-sensor-name');
            rebootSensor(sensorId, sensorName);
        });
    });

    document.querySelectorAll('.edit-settings-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const sensorId = this.getAttribute('data-sensor-id');
            const sensorName = this.getAttribute('data-sensor-name');
            const sensorLocation = this.getAttribute('data-sensor-location');
            editSensorSettings(sensorId, sensorName, sensorLocation);
        });
    });

    document.querySelectorAll('.delete-sensor-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const sensorId = this.getAttribute('data-sensor-id');
            const sensorName = this.getAttribute('data-sensor-name');
            deleteSensor(sensorId, sensorName);
        });
    });
}

function updateSensor(sensorId, sensorName) {
    // Ask for optional branch parameter
    const branch = prompt(
        `Update sensor "${sensorName}" (${sensorId})\n\n` +
        `Enter git branch name (leave empty for current branch):`,
        ''
    );

    // User cancelled
    if (branch === null) {
        return;
    }

    // Confirm update
    const branchText = branch ? ` to branch "${branch}"` : '';
    const confirmed = confirm(
        `Are you sure you want to update sensor "${sensorName}"${branchText}?\n\n` +
        `This will:\n` +
        `• Execute git pull${branch ? ' on branch ' + branch : ''}\n` +
        `• Restart the sensor service\n` +
        `• Sensor will be offline for ~10-30 seconds\n\n` +
        `Continue?`
    );

    if (!confirmed) {
        return;
    }

    console.log(`[SENSORS] Sending update command to sensor: ${sensorId}`);

    // Create command via API
    const parameters = branch ? { branch: branch } : {};

    fetch(`/api/sensors/${encodeURIComponent(sensorId)}/commands`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            command_type: 'update',
            parameters: parameters
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log(`[SENSORS] Update command queued: ${sensorId}`);
            alert(
                `Update command sent to sensor "${sensorName}"!\n\n` +
                `The sensor will:\n` +
                `1. Pull latest code from git${branch ? ' (branch: ' + branch + ')' : ''}\n` +
                `2. Restart automatically\n` +
                `3. Reconnect within ~30 seconds\n\n` +
                `Command ID: ${data.command_id}`
            );
        } else {
            console.error('[SENSORS] Update command failed:', data.error);
            alert(`Failed to send update command: ${data.error || 'Unknown error'}`);
        }
    })
    .catch(error => {
        console.error('[SENSORS] Update command error:', error);
        alert(`Error sending update command: ${error.message}`);
    });
}

function rebootSensor(sensorId, sensorName) {
    // Confirmation dialog
    const confirmed = confirm(
        `Are you sure you want to REBOOT sensor "${sensorName}" (${sensorId})?\n\n` +
        `This will:\n` +
        `• Execute "shutdown -r now" on the sensor\n` +
        `• Reboot the entire system\n` +
        `• Sensor will be offline for 1-5 minutes\n\n` +
        `⚠️  WARNING: This reboots the physical/virtual machine!\n\n` +
        `Continue with reboot?`
    );

    if (!confirmed) {
        return;
    }

    // Double confirmation for safety
    const doubleCheck = prompt(
        `⚠️  FINAL CONFIRMATION ⚠️\n\n` +
        `Type the sensor name to confirm reboot:\n` +
        `"${sensorName}"`,
        ''
    );

    if (doubleCheck !== sensorName) {
        alert('Reboot cancelled: sensor name did not match');
        return;
    }

    console.log(`[SENSORS] Sending reboot command to sensor: ${sensorId}`);

    // Create command via API
    fetch(`/api/sensors/${encodeURIComponent(sensorId)}/commands`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            command_type: 'reboot',
            parameters: {}
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log(`[SENSORS] Reboot command queued: ${sensorId}`);
            alert(
                `Reboot command sent to sensor "${sensorName}"!\n\n` +
                `The system will reboot in 5 seconds.\n` +
                `Expected downtime: 1-5 minutes\n\n` +
                `Command ID: ${data.command_id}`
            );
        } else {
            console.error('[SENSORS] Reboot command failed:', data.error);
            alert(`Failed to send reboot command: ${data.error || 'Unknown error'}`);
        }
    })
    .catch(error => {
        console.error('[SENSORS] Reboot command error:', error);
        alert(`Error sending reboot command: ${error.message}`);
    });
}

// Helper function to create interface checkbox
function createInterfaceCheckbox(ifaceName, displayName, promisc, status, isChecked) {
    const checkboxDiv = document.createElement('div');
    checkboxDiv.className = 'form-check';

    const checkbox = document.createElement('input');
    checkbox.className = 'form-check-input';
    checkbox.type = 'checkbox';
    checkbox.value = ifaceName;
    checkbox.id = `iface-${ifaceName}`;
    checkbox.checked = isChecked;

    const label = document.createElement('label');
    label.className = 'form-check-label text-light';
    label.htmlFor = `iface-${ifaceName}`;

    // Build label text with status indicator
    let labelText = displayName || ifaceName;
    let statusIndicator = '';
    let title = '';

    if (promisc !== null && status !== null) {
        // Regular interface with PROMISC status
        if (status === 'down') {
            statusIndicator = '⚪ ';
            title = 'Interface is DOWN';
            label.style.color = '#6c757d'; // Gray
        } else if (!promisc && status === 'up') {
            statusIndicator = '🔴 ';
            title = `PROMISC mode disabled. Run: sudo ip link set ${ifaceName} promisc on`;
            label.style.color = '#dc3545'; // Red
        } else if (promisc) {
            statusIndicator = '🟢 ';
            title = 'PROMISC mode enabled (ready for monitoring)';
            label.style.color = '#28a745'; // Green
        }
    } else {
        // "All Interfaces" or no status
        title = displayName === 'All Interfaces' ? 'Toggle all interfaces' : '';
    }

    label.textContent = statusIndicator + labelText;
    label.title = title;

    checkboxDiv.appendChild(checkbox);
    checkboxDiv.appendChild(label);

    return checkboxDiv;
}

async function editSensorSettings(sensorId, sensorName, currentLocation) {
    // Advanced settings editor using modal and centralized config
    console.log(`[SENSORS] Opening settings for sensor: ${sensorId}`);

    // Populate modal with sensor info
    document.getElementById('edit-sensor-id').value = sensorId;
    document.getElementById('edit-sensor-name').textContent = sensorName;
    document.getElementById('edit-sensor-id-display').textContent = sensorId;
    document.getElementById('edit-sensor-location').value = currentLocation || '';

    // Fetch current settings from config
    try {
        const response = await fetch(`/api/config?sensor_id=${encodeURIComponent(sensorId)}&include_defaults=true`);
        const result = await response.json();

        if (result.success) {
            const config = result.config;

            // Populate location (override currentLocation if set in config)
            const configLocation = config.sensor?.location;
            if (configLocation) {
                document.getElementById('edit-sensor-location').value = configLocation;
            }

            // Populate internal networks
            const internalNetworks = config.internal_networks || [];
            document.getElementById('edit-internal-networks').value = Array.isArray(internalNetworks)
                ? internalNetworks.join('\n')
                : '';

            // Populate intervals
            const heartbeatInterval = config.performance?.heartbeat_interval || 30;
            const configSyncInterval = config.performance?.config_sync_interval || 300;

            document.getElementById('edit-heartbeat-interval').value = heartbeatInterval;
            document.getElementById('edit-config-sync-interval').value = configSyncInterval;

            // Populate additional performance settings
            const batchInterval = config.performance?.batch_interval || 30;
            const metricsInterval = config.performance?.metrics_interval || 60;
            const minSeverity = config.filter?.min_severity || 'LOW';

            document.getElementById('edit-batch-interval').value = batchInterval;
            document.getElementById('edit-metrics-interval').value = metricsInterval;
            document.getElementById('edit-min-severity').value = minSeverity;

            // Populate PCAP Forensics settings
            const pcapConfig = config.thresholds?.pcap_export || {};
            document.getElementById('edit-pcap-enabled').value = String(pcapConfig.enabled !== false); // Default true
            document.getElementById('edit-pcap-upload').value = String(pcapConfig.upload_to_soc !== false); // Default true
            document.getElementById('edit-pcap-keep-local').value = String(pcapConfig.keep_local_copy === true); // Default false
            document.getElementById('edit-pcap-ram-threshold').value = pcapConfig.ram_flush_threshold || 75;
            document.getElementById('edit-pcap-output-dir').value = pcapConfig.output_dir || '/var/log/netmonitor/pcap';
        }
    } catch (error) {
        console.error('[SENSORS] Error loading current settings:', error);
    }

    // Fetch sensor metadata to get available interfaces
    try {
        const sensorResponse = await fetch(`/api/sensors/${encodeURIComponent(sensorId)}`);
        const sensorResult = await sensorResponse.json();

        if (sensorResult.success && sensorResult.data) {
            const sensor = sensorResult.data;
            const availableInterfaces = sensor.config?.available_interfaces || [];
            const currentInterface = sensor.config?.interface || 'eth0';

            const interfaceContainer = document.getElementById('edit-sensor-interface');
            interfaceContainer.innerHTML = ''; // Clear loading message

            // Parse current interface(s)
            const currentInterfaces = currentInterface.includes(',')
                ? currentInterface.split(',').map(i => i.trim())
                : [currentInterface];

            if (availableInterfaces.length === 0) {
                // No interfaces reported yet, show common defaults
                ['eth0', 'eth1', 'ens192', 'ens33'].forEach(iface => {
                    const checkboxDiv = createInterfaceCheckbox(iface, '', false, 'unknown', currentInterfaces.includes(iface));
                    interfaceContainer.appendChild(checkboxDiv);
                });
            } else {
                // Use reported interfaces from sensor (with PROMISC status)
                availableInterfaces.forEach(ifaceData => {
                    // Handle both old format (string) and new format (object)
                    const ifaceName = typeof ifaceData === 'string' ? ifaceData : ifaceData.name;
                    const promisc = typeof ifaceData === 'object' ? ifaceData.promisc : false;
                    const status = typeof ifaceData === 'object' ? ifaceData.status : 'unknown';

                    const checkboxDiv = createInterfaceCheckbox(ifaceName, '', promisc, status, currentInterfaces.includes(ifaceName));
                    interfaceContainer.appendChild(checkboxDiv);
                });
            }

            // Add "All Interfaces" checkbox at the end
            const allCheckboxDiv = createInterfaceCheckbox('all', 'All Interfaces', null, null, currentInterfaces.includes('all'));
            interfaceContainer.appendChild(allCheckboxDiv);

            // Add event listener to "All Interfaces" checkbox to toggle all
            const allCheckbox = interfaceContainer.querySelector('#iface-all');
            if (allCheckbox) {
                allCheckbox.addEventListener('change', function() {
                    const otherCheckboxes = interfaceContainer.querySelectorAll('input[type="checkbox"]:not(#iface-all)');
                    otherCheckboxes.forEach(cb => {
                        cb.checked = this.checked;
                    });
                });
            }
        } else {
            // API call failed or returned no data
            console.error('[SENSORS] Failed to load sensor metadata:', sensorResult);
            const interfaceContainer = document.getElementById('edit-sensor-interface');
            interfaceContainer.innerHTML = `
                <div class="alert alert-warning">
                    ❌ Could not load interface list. Error: ${sensorResult.error || 'Unknown error'}
                    <br><small>Check browser console for details.</small>
                </div>
            `;
        }
    } catch (error) {
        console.error('[SENSORS] Error loading sensor interfaces:', error);
        const interfaceContainer = document.getElementById('edit-sensor-interface');
        if (interfaceContainer) {
            interfaceContainer.innerHTML = `
                <div class="alert alert-danger">
                    ❌ Network error loading interfaces: ${error.message}
                    <br><small>Check browser console and network tab for details.</small>
                </div>
            `;
        }
    }

    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('editSensorModal'));
    modal.show();
}

async function saveSensorSettings() {
    const sensorId = document.getElementById('edit-sensor-id').value;
    const location = document.getElementById('edit-sensor-location').value;
    const internalNetworks = document.getElementById('edit-internal-networks').value
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0);
    const heartbeatInterval = parseInt(document.getElementById('edit-heartbeat-interval').value);
    const configSyncInterval = parseInt(document.getElementById('edit-config-sync-interval').value);

    // Network Interface(s) - read from checkboxes
    const interfaceContainer = document.getElementById('edit-sensor-interface');
    const selectedInterfaces = Array.from(interfaceContainer.querySelectorAll('input[type="checkbox"]:checked'))
        .map(cb => cb.value);
    const interfaceValue = selectedInterfaces.join(',');

    // PCAP Forensics settings
    const pcapEnabled = document.getElementById('edit-pcap-enabled').value === 'true';
    const pcapUpload = document.getElementById('edit-pcap-upload').value === 'true';
    const pcapKeepLocal = document.getElementById('edit-pcap-keep-local').value === 'true';
    const pcapRamThreshold = parseInt(document.getElementById('edit-pcap-ram-threshold').value);
    const pcapOutputDir = document.getElementById('edit-pcap-output-dir').value.trim();

    // Additional performance settings
    const batchInterval = parseInt(document.getElementById('edit-batch-interval').value);
    const metricsInterval = parseInt(document.getElementById('edit-metrics-interval').value);
    const minSeverity = document.getElementById('edit-min-severity').value;

    console.log(`[SENSORS] Saving settings for sensor ${sensorId}`);

    const saveBtn = document.getElementById('save-sensor-settings-btn');

    // Disable button during save
    saveBtn.disabled = true;
    saveBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Saving...';

    try {
        // Save each setting
        const updates = [
            {
                parameter_path: 'sensor.location',
                value: location,
                description: `Location for sensor ${sensorId}`
            },
            {
                parameter_path: 'internal_networks',
                value: internalNetworks,
                description: `Internal networks for sensor ${sensorId}`
            },
            {
                parameter_path: 'interface',
                value: interfaceValue,
                description: `Network interface(s) for sensor ${sensorId}`
            },
            {
                parameter_path: 'performance.heartbeat_interval',
                value: heartbeatInterval,
                description: `Heartbeat interval for sensor ${sensorId}`
            },
            {
                parameter_path: 'performance.config_sync_interval',
                value: configSyncInterval,
                description: `Config sync interval for sensor ${sensorId}`
            },
            // PCAP Forensics settings
            {
                parameter_path: 'thresholds.pcap_export.enabled',
                value: pcapEnabled,
                description: `PCAP capture enabled for sensor ${sensorId}`
            },
            {
                parameter_path: 'thresholds.pcap_export.upload_to_soc',
                value: pcapUpload,
                description: `PCAP upload to SOC for sensor ${sensorId}`
            },
            {
                parameter_path: 'thresholds.pcap_export.keep_local_copy',
                value: pcapKeepLocal,
                description: `Keep local PCAP copy for sensor ${sensorId}`
            },
            {
                parameter_path: 'thresholds.pcap_export.ram_flush_threshold',
                value: pcapRamThreshold,
                description: `PCAP RAM flush threshold for sensor ${sensorId}`
            },
            {
                parameter_path: 'thresholds.pcap_export.output_dir',
                value: pcapOutputDir,
                description: `PCAP output directory for sensor ${sensorId}`
            },
            // Additional performance settings
            {
                parameter_path: 'performance.batch_interval',
                value: batchInterval,
                description: `Alert batch interval for sensor ${sensorId}`
            },
            {
                parameter_path: 'performance.metrics_interval',
                value: metricsInterval,
                description: `Metrics interval for sensor ${sensorId}`
            },
            {
                parameter_path: 'filter.min_severity',
                value: minSeverity,
                description: `Minimum alert severity for sensor ${sensorId}`
            }
        ];

        let successCount = 0;
        for (const update of updates) {
            const response = await fetch('/api/config/parameter', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    parameter_path: update.parameter_path,
                    value: update.value,
                    sensor_id: sensorId,
                    scope: 'sensor',
                    description: update.description,
                    updated_by: 'dashboard'
                })
            });

            const result = await response.json();
            if (result.success) {
                successCount++;
            } else {
                console.error(`[SENSORS] Failed to update ${update.parameter_path}:`, result.error);
            }
        }

        // Show success message
        if (successCount === updates.length) {
            console.log(`[SENSORS] All settings updated successfully`);
            alert(
                `Sensor settings updated successfully!\n\n` +
                `Updated settings:\n` +
                `• Location: ${location}\n` +
                `• Internal Networks: ${internalNetworks.length} network(s)\n` +
                `• Heartbeat Interval: ${heartbeatInterval}s\n` +
                `• Config Sync Interval: ${configSyncInterval}s\n\n` +
                `The sensor will pick up these changes automatically.\n` +
                `To apply immediately, restart the sensor.`
            );

            // Close modal and reload sensors
            bootstrap.Modal.getInstance(document.getElementById('editSensorModal')).hide();
            loadSensors();
        } else {
            alert(`Warning: Only ${successCount} of ${updates.length} settings were updated successfully.`);
        }
    } catch (error) {
        console.error('[SENSORS] Error saving settings:', error);
        alert(`Error saving settings: ${error.message}`);
    } finally {
        // Re-enable button
        saveBtn.disabled = false;
        saveBtn.innerHTML = '<i class="bi bi-save"></i> Save Settings';
    }
}

function deleteSensor(sensorId, sensorName) {
    // Confirmation dialog
    const confirmed = confirm(
        `Are you sure you want to delete sensor "${sensorName}" (${sensorId})?\n\n` +
        `This will permanently remove:\n` +
        `• All sensor metrics\n` +
        `• All sensor alerts\n` +
        `• Sensor registration\n\n` +
        `This action cannot be undone!`
    );

    if (!confirmed) {
        return;
    }

    // Show loading state
    console.log(`[SENSORS] Deleting sensor: ${sensorId}`);

    // Call DELETE API
    fetch(`/api/sensors/${encodeURIComponent(sensorId)}`, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log(`[SENSORS] Sensor deleted successfully: ${sensorId}`);
            // Show success message (you can use a toast notification library here)
            alert(`Sensor "${sensorName}" deleted successfully`);
            // Reload sensors list
            loadSensors();
        } else {
            console.error('[SENSORS] Delete failed:', data.error);
            alert(`Failed to delete sensor: ${data.error || 'Unknown error'}`);
        }
    })
    .catch(error => {
        console.error('[SENSORS] Delete error:', error);
        alert(`Error deleting sensor: ${error.message}`);
    });
}

// Load sensors on page load and refresh every 30 seconds
document.addEventListener('DOMContentLoaded', function() {
    // Initial load
    setTimeout(loadSensors, 2000);  // Load after dashboard data

    // Auto-refresh every 30 seconds
    setInterval(loadSensors, 30000);
});

// ==================== Sensor Command Center ====================

function populateCommandSensorSelects() {
    fetch('/api/sensors/')
        .then(response => response.json())
        .then(data => {
            if (data.success && data.data) {
                const commandSelect = document.getElementById('command-sensor-select');
                const whitelistSelect = document.getElementById('whitelist-sensor-select');

                // Clear existing options except first
                commandSelect.innerHTML = '<option value="">-- Select Sensor --</option>';
                whitelistSelect.innerHTML = '<option value="">-- Select Sensor --</option>';

                data.data.forEach(sensor => {
                    const option1 = document.createElement('option');
                    option1.value = sensor.sensor_id;
                    option1.textContent = `${sensor.hostname} (${sensor.sensor_id})`;
                    commandSelect.appendChild(option1);

                    const option2 = document.createElement('option');
                    option2.value = sensor.sensor_id;
                    option2.textContent = `${sensor.hostname} (${sensor.sensor_id})`;
                    whitelistSelect.appendChild(option2);
                });
            }
        })
        .catch(error => console.error('Error loading sensors for selects:', error));
}

// Show/hide params based on command type
document.getElementById('command-type-select').addEventListener('change', function() {
    const paramsContainer = document.getElementById('command-params-container');
    const commandType = this.value;

    if (commandType === 'change_interval') {
        paramsContainer.style.display = 'block';
        document.getElementById('command-params').placeholder = '{"interval": 60}';
    } else {
        paramsContainer.style.display = 'none';
    }
});

// Send command button
document.getElementById('send-command-btn').addEventListener('click', function() {
    const sensorId = document.getElementById('command-sensor-select').value;
    const commandType = document.getElementById('command-type-select').value;
    const paramsInput = document.getElementById('command-params').value;
    const resultDiv = document.getElementById('command-result');
    const alertDiv = resultDiv.querySelector('.alert');

    if (!sensorId || !commandType) {
        alertDiv.className = 'alert alert-warning';
        alertDiv.textContent = 'Please select sensor and command';
        resultDiv.style.display = 'block';
        return;
    }

    let parameters = {};
    if (commandType === 'change_interval' && paramsInput) {
        try {
            parameters = JSON.parse(paramsInput);
        } catch (e) {
            alertDiv.className = 'alert alert-danger';
            alertDiv.textContent = 'Invalid JSON parameters';
            resultDiv.style.display = 'block';
            return;
        }
    }

    // Show loading
    alertDiv.className = 'alert alert-info';
    alertDiv.textContent = 'Sending command...';
    resultDiv.style.display = 'block';

    fetch(`/api/sensors/${sensorId}/commands`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            command_type: commandType,
            parameters: parameters
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alertDiv.className = 'alert alert-success';
            alertDiv.innerHTML = `<strong>Success!</strong> ${data.message}<br><small>Command ID: ${data.command_id}</small>`;
        } else {
            alertDiv.className = 'alert alert-danger';
            alertDiv.textContent = 'Error: ' + data.error;
        }
    })
    .catch(error => {
        alertDiv.className = 'alert alert-danger';
        alertDiv.textContent = 'Error: ' + error.message;
    });
});

// Command history button
document.getElementById('command-history-btn').addEventListener('click', function() {
    const sensorId = document.getElementById('command-sensor-select').value;

    if (!sensorId) {
        alert('Please select a sensor first');
        return;
    }

    fetch(`/api/sensors/${sensorId}/commands/history`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                let html = '<h6>Command History for ' + sensorId + '</h6><ul class="list-group">';
                data.commands.forEach(cmd => {
                    const statusClass = cmd.status === 'completed' ? 'success' : cmd.status === 'failed' ? 'danger' : 'warning';
                    html += `<li class="list-group-item bg-dark text-light border-secondary">
                        <strong>${cmd.command_type}</strong>
                        <span class="badge bg-${statusClass}">${cmd.status}</span><br>
                        <small>${new Date(cmd.created_at).toLocaleString()}</small>
                    </li>`;
                });
                html += '</ul>';

                const resultDiv = document.getElementById('command-result');
                const alertDiv = resultDiv.querySelector('.alert');
                alertDiv.className = 'alert alert-info';
                alertDiv.innerHTML = html;
                resultDiv.style.display = 'block';
            }
        })
        .catch(error => console.error('Error loading command history:', error));
});

// ==================== Whitelist Management ====================

// Store current whitelist entries for editing
let whitelistEntries = [];

function loadWhitelist() {
    fetch('/api/whitelist')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Sort entries by IP address (ascending)
                const sortedEntries = data.entries.sort((a, b) => {
                    // Extract IP from CIDR notation for comparison
                    const ipA = a.ip_cidr.split('/')[0];
                    const ipB = b.ip_cidr.split('/')[0];
                    // Convert IP to numeric for proper sorting
                    const numA = ipA.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
                    const numB = ipB.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
                    return numA - numB;
                });
                whitelistEntries = sortedEntries;
                updateWhitelistTable(sortedEntries);
                document.getElementById('whitelist-count').textContent = sortedEntries.length;
            }
        })
        .catch(error => console.error('Error loading whitelist:', error));
}

function getDirectionBadge(direction) {
    switch(direction) {
        case 'source':
        case 'outbound':  // legacy support
            return '<span class="badge bg-warning text-dark">Source</span>';
        case 'destination':
        case 'inbound':  // legacy support
            return '<span class="badge bg-success">Destination</span>';
        case 'both':
        default:
            return '<span class="badge bg-secondary">Both</span>';
    }
}

function updateWhitelistTable(entries) {
    const tbody = document.getElementById('whitelist-table');
    tbody.innerHTML = '';

    if (entries.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No whitelist entries</td></tr>';
        return;
    }

    entries.forEach(entry => {
        const row = document.createElement('tr');
        const scopeBadge = entry.scope === 'global'
            ? '<span class="badge bg-primary">Global</span>'
            : '<span class="badge bg-info">Sensor</span>';
        const directionBadge = getDirectionBadge(entry.direction || 'both');

        row.innerHTML = `
            <td><code>${entry.ip_cidr}</code></td>
            <td>${entry.description || '<span class="text-muted">-</span>'}</td>
            <td>${directionBadge}</td>
            <td>${scopeBadge}</td>
            <td>${entry.sensor_id || '<span class="text-muted">-</span>'}</td>
            <td><small>${new Date(entry.created_at).toLocaleString()}</small></td>
            <td>
                <button class="btn btn-sm btn-outline-primary me-1" onclick="editWhitelistEntry(${entry.id})" title="Edit">
                    <i class="bi bi-pencil"></i>
                </button>
                <button class="btn btn-sm btn-danger" onclick="deleteWhitelistEntry(${entry.id})" title="Delete">
                    <i class="bi bi-trash"></i>
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

// Show/hide sensor select based on scope
document.getElementById('whitelist-scope').addEventListener('change', function() {
    const sensorContainer = document.getElementById('whitelist-sensor-container');
    sensorContainer.style.display = this.value === 'sensor' ? 'block' : 'none';
});

// Track if we're editing an existing entry
let editingWhitelistId = null;

// Add/Update whitelist entry
document.getElementById('add-whitelist-btn').addEventListener('click', function() {
    const ipCidr = document.getElementById('whitelist-ip').value;
    const description = document.getElementById('whitelist-description').value;
    const direction = document.getElementById('whitelist-direction').value;
    const scope = document.getElementById('whitelist-scope').value;
    const sensorId = scope === 'sensor' ? document.getElementById('whitelist-sensor-select').value : null;

    if (!ipCidr) {
        alert('Please enter IP/CIDR');
        return;
    }

    if (scope === 'sensor' && !sensorId) {
        alert('Please select a sensor for sensor-specific whitelist');
        return;
    }

    // If editing, delete old entry first then add new one
    const saveEntry = () => {
        fetch('/api/whitelist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ip_cidr: ipCidr,
                description: description,
                direction: direction,
                scope: scope,
                sensor_id: sensorId
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Clear form and reset state
                clearWhitelistForm();
                loadWhitelist();
            } else {
                alert('Error: ' + data.error);
            }
        })
        .catch(error => alert('Error: ' + error.message));
    };

    if (editingWhitelistId) {
        // Delete old entry first, then save new
        fetch(`/api/whitelist/${editingWhitelistId}`, { method: 'DELETE' })
            .then(() => saveEntry())
            .catch(error => alert('Error updating: ' + error.message));
    } else {
        saveEntry();
    }
});

// Clear whitelist form
function clearWhitelistForm() {
    document.getElementById('whitelist-ip').value = '';
    document.getElementById('whitelist-description').value = '';
    document.getElementById('whitelist-direction').value = 'both';
    document.getElementById('whitelist-scope').value = 'global';
    document.getElementById('whitelist-sensor-container').style.display = 'none';
    editingWhitelistId = null;
    document.getElementById('add-whitelist-btn').innerHTML = '<i class="bi bi-plus-circle"></i> Add';
}

// Edit whitelist entry - populate form with existing values
window.editWhitelistEntry = function(entryId) {
    const entry = whitelistEntries.find(e => e.id === entryId);
    if (!entry) {
        alert('Entry not found');
        return;
    }

    // Populate form
    document.getElementById('whitelist-ip').value = entry.ip_cidr;
    document.getElementById('whitelist-description').value = entry.description || '';
    // Map legacy values to new terminology
    let direction = entry.direction || 'both';
    if (direction === 'inbound') direction = 'destination';
    if (direction === 'outbound') direction = 'source';
    document.getElementById('whitelist-direction').value = direction;
    document.getElementById('whitelist-scope').value = entry.scope;

    if (entry.scope === 'sensor') {
        document.getElementById('whitelist-sensor-container').style.display = 'block';
        document.getElementById('whitelist-sensor-select').value = entry.sensor_id || '';
    } else {
        document.getElementById('whitelist-sensor-container').style.display = 'none';
    }

    // Set editing state
    editingWhitelistId = entryId;
    document.getElementById('add-whitelist-btn').innerHTML = '<i class="bi bi-check-circle"></i> Update';

    // Scroll to form
    document.getElementById('whitelist-ip').focus();
};

// Delete whitelist entry
window.deleteWhitelistEntry = function(entryId) {
    if (!confirm('Are you sure you want to delete this whitelist entry?')) {
        return;
    }

    fetch(`/api/whitelist/${entryId}`, {
        method: 'DELETE'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // If we were editing this entry, clear the form
            if (editingWhitelistId === entryId) {
                clearWhitelistForm();
            }
            loadWhitelist();
        } else {
            alert('Error: ' + data.error);
        }
    })
    .catch(error => alert('Error: ' + error.message));
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(() => {
        populateCommandSensorSelects();
        loadWhitelist();
    }, 2000);

    // Auto-refresh whitelist every 60 seconds
    setInterval(loadWhitelist, 60000);
});

// ==================== Integrations Status ====================

function loadIntegrationStatus() {
    fetch('/api/integrations/status')
        .then(response => response.json())
        .then(data => {
            if (!data.success) return;

            const status = data.data;
            const integrationsRow = document.getElementById('integrations-row');

            // Only show if integrations are enabled
            if (!status.enabled) {
                if (integrationsRow) integrationsRow.style.display = 'none';
                return;
            }

            // Show the integrations row
            if (integrationsRow) integrationsRow.style.display = '';

            // Update count badge
            const countBadge = document.getElementById('integrations-count');
            const totalCount = (status.siem?.length || 0) + (status.threat_intel?.length || 0);
            if (countBadge) countBadge.textContent = totalCount;

            // Render SIEM integrations
            const siemContainer = document.getElementById('siem-integrations');
            if (siemContainer) {
                if (status.siem && status.siem.length > 0) {
                    siemContainer.innerHTML = status.siem.map(int => renderIntegrationCard(int, 'siem')).join('');
                } else {
                    siemContainer.innerHTML = '<span class="text-muted">No SIEM integrations enabled</span>';
                }
            }

            // Render Threat Intel integrations
            const tiContainer = document.getElementById('threat-intel-integrations');
            if (tiContainer) {
                if (status.threat_intel && status.threat_intel.length > 0) {
                    tiContainer.innerHTML = status.threat_intel.map(int => renderIntegrationCard(int, 'threat_intel')).join('');
                } else {
                    tiContainer.innerHTML = '<span class="text-muted">No threat intel integrations enabled</span>';
                }
            }
        })
        .catch(error => {
            console.error('Error loading integration status:', error);
        });
}

function renderIntegrationCard(integration, type) {
    const hasCredentials = integration.has_credentials;
    const statusIcon = hasCredentials ? 'bi-check-circle-fill text-success' : 'bi-exclamation-circle-fill text-warning';
    const statusText = hasCredentials ? 'Configured' : 'Missing credentials';

    let details = '';
    if (integration.url) {
        details = `<small class="text-light opacity-75">${integration.url}</small>`;
    } else if (integration.host) {
        details = `<small class="text-light opacity-75">${integration.host}:${integration.port} (${integration.format})</small>`;
    } else if (integration.api_url) {
        details = `<small class="text-light opacity-75">${integration.api_url}</small>`;
    }

    return `
        <div class="d-flex align-items-center justify-content-between mb-2 p-2 bg-dark rounded border border-secondary">
            <div>
                <strong class="text-white">${integration.display_name}</strong><br>
                ${details}
            </div>
            <div class="text-end">
                <i class="bi ${statusIcon}" title="${statusText}"></i>
                <button class="btn btn-sm btn-outline-light ms-2" onclick="testIntegration('${integration.name}')" title="Test connection">
                    <i class="bi bi-arrow-repeat"></i>
                </button>
            </div>
        </div>
    `;
}

window.testIntegration = function(name) {
    const btn = event.target.closest('button');
    const originalContent = btn.innerHTML;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
    btn.disabled = true;

    fetch(`/api/integrations/test/${name}`, { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            btn.innerHTML = originalContent;
            btn.disabled = false;

            if (data.success) {
                showToast(`${name}: ${data.message}`, 'success');
            } else {
                showToast(`${name}: ${data.message}`, 'danger');
            }
        })
        .catch(error => {
            btn.innerHTML = originalContent;
            btn.disabled = false;
            showToast(`${name}: ${error.message}`, 'danger');
        });
};

function showToast(message, type = 'info') {
    // Simple toast notification
    const toast = document.createElement('div');
    toast.className = `alert alert-${type} position-fixed`;
    toast.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    toast.innerHTML = `
        ${message}
        <button type="button" class="btn-close" onclick="this.parentElement.remove()"></button>
    `;
    document.body.appendChild(toast);

    // Auto-remove after 5 seconds
    setTimeout(() => toast.remove(), 5000);
}

// Load integrations on page load
document.addEventListener('DOMContentLoaded', function() {
    // Load integration status (with slight delay to avoid blocking main dashboard)
    setTimeout(loadIntegrationStatus, 1500);

    // Refresh integration status every 60 seconds
    setInterval(loadIntegrationStatus, 60000);

    // Load disk usage (initial + refresh every 60 seconds)
    // Call immediately after DOM is ready (charts should be initialized by now)
    setTimeout(loadDiskUsage, 500);  // Short delay to ensure gauges are ready
    setInterval(loadDiskUsage, 60000);
});

// ==================== Disk Usage & Data Retention ====================

async function loadDiskUsage() {
    try {
        const response = await fetch('/api/disk-usage');
        const result = await response.json();

        if (result.success) {
            console.log('[Disk Usage] Data loaded:', result.data);
            updateDiskUsage(result.data);
        } else {
            console.error('[Disk Usage] Error loading:', result.error);
        }
    } catch (error) {
        console.error('[Disk Usage] Error fetching:', error);
    }
}

function updateDiskUsage(data) {
    console.log('[Disk Usage] Full data received:', data);

    // Check if disk gauge is initialized
    if (!diskGauge) {
        console.warn('[Disk Usage] Gauge not yet initialized, skipping update');
        return;
    }

    // Update disk usage gauge
    const diskPercent = data.system?.percent_used || 0;
    console.log('[Disk Usage] System data:', data.system);
    console.log('[Disk Usage] Database data:', data.database);
    console.log('[Disk Usage] Retention data:', data.retention);
    console.log('[Disk Usage] Disk percent:', diskPercent);

    console.log('[Disk Usage] Attempting to update gauge...');
    try {
        updateGauge(diskGauge, diskPercent, 100);
        console.log('[Disk Usage] Gauge updated successfully');
    } catch (e) {
        console.error('[Disk Usage] Error updating gauge:', e);
    }

    console.log('[Disk Usage] Updating disk-value element...');
    const diskValueEl = document.getElementById('disk-value');
    if (diskValueEl) {
        diskValueEl.textContent = diskPercent.toFixed(1) + '%';
        console.log('[Disk Usage] disk-value updated to:', diskValueEl.textContent);
    } else {
        console.error('[Disk Usage] Element disk-value not found!');
    }

    // Update disk details
    console.log('[Disk Usage] Updating disk-details...');
    const diskUsed = data.system?.used_human || '0 GB';
    const diskTotal = data.system?.total_human || '0 GB';
    const diskDetailsEl = document.getElementById('disk-details');
    if (diskDetailsEl) {
        diskDetailsEl.textContent = `${diskUsed} / ${diskTotal}`;
        console.log('[Disk Usage] disk-details updated to:', diskDetailsEl.textContent);
    } else {
        console.error('[Disk Usage] Element disk-details not found!');
    }

    // Update database size (DB + PCAP combined)
    const dbSizeHuman = data.database?.size_human || '0 MB';
    const pcapSizeHuman = data.pcap?.size_human || '0 MB';
    const dbSize = data.database?.size_bytes || 0;
    const pcapSize = data.pcap?.size_bytes || 0;

    // Format combined size
    const totalSizeBytes = dbSize + pcapSize;
    let totalSizeText = '0 B';
    if (totalSizeBytes >= 1024 * 1024 * 1024) {
        totalSizeText = (totalSizeBytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
    } else if (totalSizeBytes >= 1024 * 1024) {
        totalSizeText = (totalSizeBytes / (1024 * 1024)).toFixed(2) + ' MB';
    } else if (totalSizeBytes >= 1024) {
        totalSizeText = (totalSizeBytes / 1024).toFixed(2) + ' KB';
    } else {
        totalSizeText = totalSizeBytes + ' B';
    }

    document.getElementById('db-size-value').textContent = totalSizeText;

    // Update counts - show DB alerts/metrics and PCAP files
    const alertsText = formatNumber(data.database?.alerts_count || 0);
    const pcapText = formatNumber(data.pcap?.file_count || 0);
    document.getElementById('db-alerts-count').textContent = alertsText;
    document.getElementById('db-metrics-count').textContent = `${formatNumber(data.database?.metrics_count || 0)} metrics`;

    // Add PCAP info to metrics display
    const metricsEl = document.getElementById('db-metrics-count');
    if (metricsEl && data.pcap?.file_count > 0) {
        metricsEl.textContent = `${formatNumber(data.database?.metrics_count || 0)} metrics • ${pcapText} pcaps`;
    }

    // Update data age
    const dataAge = data.database?.data_age_days || 0;
    document.getElementById('data-age').textContent = `${dataAge} days`;

    // Update retention settings
    if (data.retention) {
        document.getElementById('retention-alerts').textContent = data.retention.alerts_days + 'd';
        document.getElementById('retention-metrics').textContent = data.retention.metrics_days + 'd';
    }

    // Color code disk usage
    const diskCard = document.getElementById('diskGauge').closest('.card');
    if (diskPercent > 90) {
        diskCard.classList.remove('bg-secondary');
        diskCard.classList.add('bg-danger');
    } else if (diskPercent > 75) {
        diskCard.classList.remove('bg-secondary', 'bg-danger');
        diskCard.classList.add('bg-warning');
    } else {
        diskCard.classList.remove('bg-danger', 'bg-warning');
        diskCard.classList.add('bg-secondary');
    }
}

async function triggerDataCleanup() {
    const btn = document.getElementById('cleanup-btn');
    const originalText = btn.innerHTML;

    if (!confirm('Are you sure you want to run data cleanup now?\n\nThis will delete old data according to the retention policy.')) {
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<i class="spinner-border spinner-border-sm"></i> Cleaning...';

    try {
        const response = await fetch('/api/data-retention/cleanup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const result = await response.json();

        if (result.success) {
            alert(`✅ Cleanup completed!\n\nDeleted records:\n${JSON.stringify(result.data.deleted, null, 2)}`);
            document.getElementById('last-cleanup').textContent = 'Last cleanup: Just now';

            // Reload disk usage to show updated stats
            loadDiskUsage();
        } else {
            alert('❌ Cleanup failed: ' + result.error);
        }
    } catch (error) {
        console.error('Error triggering cleanup:', error);
        alert('❌ Error: ' + error.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
}

function showRetentionSettings() {
    alert('Retention settings are configured in config.yaml\n\nCurrent settings:\n- Alerts: 365 days (NIS-2 minimum)\n- Metrics: 90 days\n- Audit logs: 730 days (NIS-2 minimum)\n\nTo change these values, edit the data_retention section in config.yaml and restart the SOC server.');
}

function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

// ==================== Export for debugging ====================

window.dashboardDebug = {
    socket,
    trafficChart,
    alertPieChart,
    loadDashboardData,
    updateMetrics,
    loadSensors,
    loadIntegrationStatus
};
