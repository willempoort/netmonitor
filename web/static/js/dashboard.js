// Network Monitor Dashboard JavaScript

// Global variables
let socket;
let trafficChart;
let alertPieChart;
let packetsGauge, alertsGauge, cpuGauge, memoryGauge;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    console.log('Initializing Network Monitor Dashboard...');

    // Initialize WebSocket
    initWebSocket();

    // Initialize charts
    initCharts();

    // Load initial data
    loadDashboardData();

    // Update clock
    updateClock();
    setInterval(updateClock, 1000);

    // Auto-refresh data every 30 seconds
    setInterval(loadDashboardData, 30000);
});

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
        console.log('Metrics update received');
        updateMetrics(metrics);
    });

    socket.on('dashboard_update', function(data) {
        console.log('Dashboard update received');
        updateDashboard(data);
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
    try {
        const response = await fetch('/api/dashboard');
        const result = await response.json();

        if (result.success) {
            updateDashboard(result.data);
        } else {
            console.error('Error loading dashboard data:', result.error);
        }
    } catch (error) {
        console.error('Error fetching dashboard data:', error);
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
            const item = document.createElement('div');
            item.className = 'list-group-item bg-dark d-flex justify-content-between align-items-center';
            item.innerHTML = `
                <span>${type.replace(/_/g, ' ')}</span>
                <span class="badge bg-danger rounded-pill">${count}</span>
            `;
            list.appendChild(item);
        });
    }
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

        row.innerHTML = `
            <td>
                <small>${talker.ip_address}</small>
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

// ==================== Export for debugging ====================

window.dashboardDebug = {
    socket,
    trafficChart,
    alertPieChart,
    loadDashboardData,
    updateMetrics
};
