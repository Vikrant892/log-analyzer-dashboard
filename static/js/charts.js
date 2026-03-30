/*
 * chart.js visualizations for the dashboard
 * pulls data from the stats object injected by flask
 * nothing too clever — just bar charts and pie charts
 */

// color palette matching the dark theme
const COLORS = {
    green: '#00ff41',
    greenDim: '#00cc33',
    cyan: '#00d4ff',
    red: '#ff4444',
    orange: '#ff8c00',
    yellow: '#ffd700',
    purple: '#a855f7',
    pink: '#ec4899',
    teal: '#14b8a6',
    indigo: '#6366f1',
};

// chart.js global defaults — dark theme friendly
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#30363d';
Chart.defaults.font.family = "'Courier New', monospace";
Chart.defaults.font.size = 11;

// bail out if no stats
if (typeof stats !== 'undefined' && stats && stats.total_events > 0) {
    renderCharts(stats);
}

function renderCharts(data) {
    // --- top IPs bar chart ---
    const ipLabels = Object.keys(data.top_ips || {});
    const ipValues = Object.values(data.top_ips || {});

    if (ipLabels.length > 0) {
        new Chart(document.getElementById('topIpsChart'), {
            type: 'bar',
            data: {
                labels: ipLabels,
                datasets: [{
                    label: 'Events',
                    data: ipValues,
                    backgroundColor: ipValues.map((_, i) =>
                        i === 0 ? COLORS.red : COLORS.cyan + '99'
                    ),
                    borderColor: ipValues.map((_, i) =>
                        i === 0 ? COLORS.red : COLORS.cyan
                    ),
                    borderWidth: 1,
                    borderRadius: 3,
                }]
            },
            options: {
                indexAxis: 'y',  // horizontal bar
                responsive: true,
                plugins: {
                    legend: { display: false },
                },
                scales: {
                    x: { grid: { color: '#21262d' } },
                    y: { grid: { display: false } },
                }
            }
        });
    }

    // --- severity pie chart ---
    const sevData = data.severity_breakdown || {};
    const sevColors = {
        'critical': COLORS.red,
        'high': COLORS.orange,
        'warning': COLORS.yellow,
        'info': COLORS.cyan,
    };

    if (Object.keys(sevData).length > 0) {
        new Chart(document.getElementById('severityChart'), {
            type: 'doughnut',
            data: {
                labels: Object.keys(sevData),
                datasets: [{
                    data: Object.values(sevData),
                    backgroundColor: Object.keys(sevData).map(k => sevColors[k] || COLORS.teal),
                    borderColor: '#0d1117',
                    borderWidth: 2,
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { padding: 15, usePointStyle: true },
                    }
                }
            }
        });
    }

    // --- event types bar chart ---
    const etData = data.event_types || {};
    const etColors = [COLORS.green, COLORS.cyan, COLORS.orange, COLORS.purple, COLORS.pink, COLORS.teal];

    if (Object.keys(etData).length > 0) {
        new Chart(document.getElementById('eventTypeChart'), {
            type: 'bar',
            data: {
                labels: Object.keys(etData),
                datasets: [{
                    label: 'Count',
                    data: Object.values(etData),
                    backgroundColor: Object.keys(etData).map((_, i) => etColors[i % etColors.length] + '88'),
                    borderColor: Object.keys(etData).map((_, i) => etColors[i % etColors.length]),
                    borderWidth: 1,
                    borderRadius: 3,
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false } },
                    y: { grid: { color: '#21262d' } },
                }
            }
        });
    }

    // --- timeline chart ---
    const tlData = data.events_by_hour || {};

    if (Object.keys(tlData).length > 0) {
        new Chart(document.getElementById('timelineChart'), {
            type: 'line',
            data: {
                labels: Object.keys(tlData),
                datasets: [{
                    label: 'Events',
                    data: Object.values(tlData),
                    borderColor: COLORS.green,
                    backgroundColor: COLORS.green + '15',
                    fill: true,
                    tension: 0.3,
                    pointBackgroundColor: COLORS.green,
                    pointRadius: 3,
                    pointHoverRadius: 6,
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: '#21262d' } },
                    y: {
                        grid: { color: '#21262d' },
                        beginAtZero: true,
                    },
                }
            }
        });
    }
}
