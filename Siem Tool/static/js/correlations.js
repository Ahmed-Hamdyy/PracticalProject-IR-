class CorrelationsManager {
    constructor() {
        this.correlationContainer = document.getElementById('correlationContainer');
        this.timeWindow = document.getElementById('timeWindow');
        this.refreshButton = document.getElementById('refreshCorrelations');
        this.patternType = document.getElementById('patternType');
        
        this.setupEventListeners();
        this.loadCorrelations();
    }

    setupEventListeners() {
        if (this.refreshButton) {
            this.refreshButton.addEventListener('click', () => this.loadCorrelations());
        }
        if (this.timeWindow) {
            this.timeWindow.addEventListener('change', () => this.loadCorrelations());
        }
        if (this.patternType) {
            this.patternType.addEventListener('change', () => this.filterCorrelations());
        }
    }

    async loadCorrelations() {
        try {
            const response = await fetch('/correlations');
            const data = await response.json();
            
            if (data.status === 'success' && data.correlations) {
                this.displayCorrelations(data.correlations);
                this.updateStats(data.correlations);
            }
        } catch (error) {
            console.error('Error loading correlations:', error);
        }
    }

    updateStats(correlations) {
        // Update overview stats
        document.getElementById('totalCorrelations').textContent = correlations.length;
        document.getElementById('activePatterns').textContent = 
            new Set(correlations.map(c => c.type)).size;
        
        // Calculate security score based on correlation severity
        const score = Math.max(0, 100 - (correlations.length * 5));
        document.getElementById('securityScore').textContent = score;
    }

    filterCorrelations() {
        const selectedType = this.patternType.value.toLowerCase();
        const cards = this.correlationContainer.querySelectorAll('.correlation-card');
        
        cards.forEach(card => {
            const cardType = card.getAttribute('data-type');
            if (!selectedType || cardType.includes(selectedType)) {
                card.style.display = 'block';
            } else {
                card.style.display = 'none';
            }
        });
    }

    getCorrelationIcon(type) {
        const iconMap = {
            'potential brute force attack': 'fas fa-user-shield',
            'potential reconnaissance activity': 'fas fa-search',
            'suspicious account activity': 'fas fa-user-secret',
            'system state changes': 'fas fa-cogs',
            'application issues': 'fas fa-exclamation-triangle',
            'powershell activity': 'fas fa-terminal'
        };
        
        return iconMap[type.toLowerCase()] || 'fas fa-shield-alt';
    }

    displayCorrelations(correlations) {
        if (!this.correlationContainer) return;
        
        this.correlationContainer.innerHTML = '';
        
        if (correlations.length === 0) {
            this.correlationContainer.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-shield-alt"></i>
                    <p>No correlations detected</p>
                </div>
            `;
            return;
        }

        correlations.forEach(correlation => {
            const card = this.createCorrelationCard(correlation);
            this.correlationContainer.appendChild(card);
        });
    }

    createCorrelationCard(correlation) {
        const card = document.createElement('div');
        card.className = 'correlation-card';
        card.setAttribute('data-type', correlation.type.toLowerCase());
        
        const icon = this.getCorrelationIcon(correlation.type);
        
        // Create summary items based on correlation type
        let summaryItems = '';
        if (correlation.summary) {
            const summary = correlation.summary;
            switch (correlation.type.toLowerCase()) {
                case 'potential brute force attack':
                    summaryItems = `
                        <div class="summary-item">
                            <span class="summary-label">Total Attempts:</span>
                            <span class="summary-value">${summary.total_attempts}</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-label">Time Span:</span>
                            <span class="summary-value">${summary.time_span}</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-label">Target Accounts:</span>
                            <span class="summary-value">${summary.target_accounts.join(', ')}</span>
                        </div>
                    `;
                    break;
                case 'potential reconnaissance activity':
                    summaryItems = `
                        <div class="summary-item">
                            <span class="summary-label">Total Commands:</span>
                            <span class="summary-value">${summary.total_commands}</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-label">Time Span:</span>
                            <span class="summary-value">${summary.time_span}</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-label">Command Sources:</span>
                            <span class="summary-value">${summary.command_sources.join(', ')}</span>
                        </div>
                    `;
                    break;
                case 'suspicious account activity':
                    summaryItems = `
                        <div class="summary-item">
                            <span class="summary-label">Account Changes:</span>
                            <span class="summary-value">${summary.account_changes}</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-label">Commands Executed:</span>
                            <span class="summary-value">${summary.commands_executed}</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-label">Time Span:</span>
                            <span class="summary-value">${summary.time_span}</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-label">Affected Accounts:</span>
                            <span class="summary-value">${summary.affected_accounts.join(', ')}</span>
                        </div>
                    `;
                    break;
                case 'system state changes':
                    summaryItems = `
                        <div class="summary-item">
                            <span class="summary-label">Total Changes:</span>
                            <span class="summary-value">${summary.total_changes}</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-label">Time Span:</span>
                            <span class="summary-value">${summary.time_span}</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-label">Event Sources:</span>
                            <span class="summary-value">${summary.event_sources.join(', ')}</span>
                        </div>
                    `;
                    break;
                case 'application issues':
                    summaryItems = `
                        <div class="summary-item">
                            <span class="summary-label">Total Errors:</span>
                            <span class="summary-value">${summary.total_errors}</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-label">Time Span:</span>
                            <span class="summary-value">${summary.time_span}</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-label">Affected Applications:</span>
                            <span class="summary-value">${summary.affected_applications.join(', ')}</span>
                        </div>
                    `;
                    break;
                case 'powershell activity':
                    summaryItems = `
                        <div class="summary-item">
                            <span class="summary-label">Total Events:</span>
                            <span class="summary-value">${summary.total_events}</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-label">Execution Context:</span>
                            <span class="summary-value">${summary.execution_context.join(', ')}</span>
                        </div>
                    `;
                    break;
            }
        }

        // Function to format event details
        const formatEventDetails = (details) => {
            if (!details) return '';
            return Object.entries(details)
                .map(([key, value]) => `
                    <div class="detail-item">
                        <span class="detail-label">${key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}:</span>
                        <span class="detail-value">${value}</span>
                    </div>
                `).join('');
        };
        
        card.innerHTML = `
            <div class="correlation-header">
                <div class="correlation-icon">
                    <i class="${icon}"></i>
                </div>
                <div class="correlation-title">
                    <h3>${correlation.type}</h3>
                    <span class="correlation-timestamp">${new Date(correlation.timestamp).toLocaleString()}</span>
                </div>
            </div>
            <div class="correlation-body">
                <p class="correlation-details">${correlation.details}</p>
                <div class="correlation-summary">
                    ${summaryItems}
                </div>
                <div class="related-events">
                    <h4>Related Events</h4>
                    ${correlation.events.map(event => `
                        <div class="event-card">
                            <div class="event-header">
                                <div class="event-main-info">
                                    <span class="event-id">Event ID: ${event.event_id}</span>
                                    <span class="event-type">${event.log_type}</span>
                                    <span class="event-source">${event.source}</span>
                                </div>
                                <span class="event-time">${new Date(event.timestamp).toLocaleString()}</span>
                            </div>
                            ${event.alert_message ? `
                                <div class="event-alert">
                                    <i class="fas fa-exclamation-triangle"></i>
                                    ${event.alert_message}
                                </div>
                            ` : ''}
                            <div class="event-details">
                                ${formatEventDetails(event.details)}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;

        return card;
    }
}

// Initialize when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.correlationsManager = new CorrelationsManager();
}); 