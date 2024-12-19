class Analytics {
    constructor() {
        this.charts = {};
        this.setupEventListeners();
        this.loadData();
    }

    setupEventListeners() {
        document.getElementById('refreshData').addEventListener('click', () => this.loadData());
    }

    async loadData() {
        try {
            const response = await fetch('/get_analytics_data');
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();
            this.updateUI(data);
        } catch (error) {
            console.error('Error loading analytics data:', error);
        }
    }

    updateUI(data) {
        // Update stats
        document.querySelector('#totalEvents .stat-value').textContent = data.total_events;
        document.querySelector('#totalAlerts .stat-value').textContent = data.total_alerts;
        document.querySelector('#commandExecutions .stat-value').textContent = 
            Object.values(data.command_stats).reduce((a, b) => a + b, 0);

        // Update charts
        this.updateEventDistributionChart(data.event_distribution);
        this.updateAlertTypesChart(data.alert_types);
        this.updateCommandAnalysisChart(data.command_stats);
    }

    updateEventDistributionChart(data) {
        const ctx = document.getElementById('eventDistributionChart');
        
        if (this.charts.eventDistribution) {
            this.charts.eventDistribution.destroy();
        }

        this.charts.eventDistribution = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: Object.keys(data),
                datasets: [{
                    data: Object.values(data),
                    backgroundColor: [
                        'rgba(52, 152, 219, 0.8)',
                        'rgba(46, 204, 113, 0.8)',
                        'rgba(231, 76, 60, 0.8)'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#ecf0f1'
                        }
                    }
                }
            }
        });
    }

    updateAlertTypesChart(data) {
        const ctx = document.getElementById('alertTypesChart');
        
        if (this.charts.alertTypes) {
            this.charts.alertTypes.destroy();
        }

        this.charts.alertTypes = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: Object.keys(data),
                datasets: [{
                    label: 'Number of Alerts',
                    data: Object.values(data),
                    backgroundColor: 'rgba(52, 152, 219, 0.8)',
                    borderColor: 'rgba(52, 152, 219, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: '#ecf0f1'
                        },
                        grid: {
                            color: 'rgba(236, 240, 241, 0.1)'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#ecf0f1',
                            maxRotation: 45,
                            minRotation: 45
                        },
                        grid: {
                            color: 'rgba(236, 240, 241, 0.1)'
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#ecf0f1'
                        }
                    }
                }
            }
        });
    }

    updateCommandAnalysisChart(data) {
        const ctx = document.getElementById('commandAnalysisChart');
        
        if (this.charts.commandAnalysis) {
            this.charts.commandAnalysis.destroy();
        }

        this.charts.commandAnalysis = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: Object.keys(data),
                datasets: [{
                    data: Object.values(data),
                    backgroundColor: [
                        'rgba(52, 152, 219, 0.8)',
                        'rgba(46, 204, 113, 0.8)',
                        'rgba(231, 76, 60, 0.8)',
                        'rgba(241, 196, 15, 0.8)',
                        'rgba(155, 89, 182, 0.8)'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#ecf0f1'
                        }
                    }
                }
            }
        });
    }
}

// Initialize analytics when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.analytics = new Analytics();
}); 