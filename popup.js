document.addEventListener('DOMContentLoaded', () => {
    const mainToggle = document.getElementById('main-toggle');
    const protectionToggle = document.getElementById('protection-toggle');

    const statusCard = document.getElementById('status-card');
    const currentStatus = document.getElementById('current-status');
    const riskScore = document.getElementById('risk-score');
    const currentDomain = document.getElementById('current-domain');
    const reasonsList = document.getElementById('reasons-list');

    const soundToggle = document.getElementById('sound-toggle');

    // Load state
    chrome.storage.local.get({ enabled: true, protectionMode: true, soundAlerts: true }, (data) => {
        if (mainToggle) mainToggle.checked = data.enabled;
        if (protectionToggle) protectionToggle.checked = data.protectionMode;
        if (soundToggle) soundToggle.checked = data.soundAlerts;
        
        toggleUIState(data.enabled);
    });

    // Toggle listeners
    if (mainToggle) {
        mainToggle.addEventListener('change', (e) => {
            const isEnabled = e.target.checked;
            chrome.storage.local.set({ enabled: isEnabled });
            toggleUIState(isEnabled);
        });
    }

    if (protectionToggle) {
        protectionToggle.addEventListener('change', (e) => {
            chrome.storage.local.set({ protectionMode: e.target.checked });
        });
    }

    if (soundToggle) {
        soundToggle.addEventListener('change', (e) => {
            chrome.storage.local.set({ soundAlerts: e.target.checked });
        });
    }

    const reasonsToggle = document.getElementById('reasons-toggle');
    if (reasonsToggle) {
        reasonsToggle.addEventListener('click', function() {
            const body = document.getElementById('reasons-body');
            const icon = this.querySelector('.toggle-icon');
            if (body.style.display === 'none') {
                body.style.display = 'block';
                icon.textContent = '▲';
            } else {
                body.style.display = 'none';
                icon.textContent = '▼';
            }
        });
    }


    function toggleUIState(isEnabled) {
        const aiCard = document.getElementById('ai-analysis-card');
        if (!isEnabled) {
            statusCard.className = 'card status-card';
            document.body.className = '';
            currentStatus.textContent = 'Disabled';
            currentStatus.style.color = '#64748b';
            riskScore.textContent = '--/100';
            reasonsList.innerHTML = '<li>PhishNetra is currently turned off.</li>';
            protectionToggle.disabled = true;
            
            // Clear progress blocks
            document.querySelectorAll('.meter-block').forEach(b => b.classList.remove('active'));

            // Clear Website Information
            const domainEl = document.getElementById('info-domain');
            const sslEl = document.getElementById('info-ssl');
            const ageEl = document.getElementById('info-age');
            if (domainEl) domainEl.textContent = '...';
            if (sslEl) sslEl.textContent = '...';
            if (ageEl) ageEl.textContent = '...';

            // Hide and clear AI Card
            if (aiCard) {
                aiCard.style.display = 'none';
                document.getElementById('ai-content-score').textContent = '0%';
                document.getElementById('ai-threats-count').textContent = '0 Detected';
                document.getElementById('ai-verdict-text').textContent = 'Analyzing page content...';
                document.getElementById('threat-badges-container').innerHTML = '';
            }
        } else {
            protectionToggle.disabled = false;
            currentStatus.style.color = '';
            fetchTabInfo();
        }
    }

    function fetchTabInfo() {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs.length === 0) return;
            let urlStr = tabs[0].url || '';

            if (urlStr.startsWith('chrome-extension://') && (urlStr.includes('warning.html') || urlStr.includes('blocked.html'))) {
                try {
                    const u = new URL(urlStr);
                    const originalUrl = u.searchParams.get('url');
                    if (originalUrl) urlStr = decodeURIComponent(originalUrl);
                } catch(e) {}
            }

            let hostname = 'Unknown';
            try {
                const url = new URL(urlStr);
                currentDomain.textContent = url.hostname;
                hostname = url.hostname;
            } catch (e) {
                currentDomain.textContent = 'Extension Page or Blank';
                return;
            }

            chrome.runtime.sendMessage({ type: 'GET_TAB_INFO' }, (response) => {
                if (!response || response.error) {
                    reasonsList.innerHTML = '<li>Unable to analyze this page.</li>';
                    return;
                }

                // Destructure all required data, including the content analysis payload, pre-fetched SSL state, and domain age
                const { score, reasons, status, isHttps, domainAge, contentRiskScore, aiVerdict, detectedThreats } = response;

                currentStatus.style.color = '';
                currentStatus.textContent = status;
                riskScore.textContent = `${score}/100`;

                // Reset body class and set status-specific class
                document.body.className = '';
                
                statusCard.className = 'card status-card';
                if (status === 'Safe') {
                    statusCard.classList.add('status-safe');
                    document.body.classList.add('body-safe');
                } else if (status === 'Suspicious') {
                    statusCard.classList.add('status-suspicious');
                    document.body.classList.add('body-suspicious');
                } else if (status === 'Dangerous') {
                    statusCard.classList.add('status-dangerous');
                    document.body.classList.add('body-dangerous');
                }

                // Update 10 segmented progress blocks dynamically
                const activeBlocks = Math.floor(score / 10);
                document.querySelectorAll('.meter-block').forEach((block, idx) => {
                    if (idx < activeBlocks) {
                        block.classList.add('active');
                    } else {
                        block.classList.remove('active');
                    }
                });

                // Update Website Information Card elements dynamically using background verified states
                const domainEl = document.getElementById('info-domain');
                const sslEl = document.getElementById('info-ssl');
                const ageEl = document.getElementById('info-age');

                if (domainEl) {
                    let displayDomain = hostname;
                    if (displayDomain.length > 14) {
                        displayDomain = displayDomain.substring(0, 12) + '...';
                    }
                    domainEl.textContent = displayDomain;
                    domainEl.title = hostname;
                }

                if (sslEl) {
                    if (isHttps) {
                        sslEl.innerHTML = '<span style="color: #10b981;">🔒 Secure</span>';
                    } else {
                        sslEl.innerHTML = '<span style="color: #ef4444;">🔓 Insecure</span>';
                    }
                }

                if (ageEl) {
                    // Instantly update from pre-fetched background value
                    ageEl.textContent = domainAge || 'age unavailable';
                }

                // Render the premium AI Content Scan Card
                const aiCard = document.getElementById('ai-analysis-card');
                if (aiCard && contentRiskScore !== undefined) {
                    aiCard.style.display = 'block';
                    
                    // Animate metrics
                    document.getElementById('ai-content-score').textContent = `${contentRiskScore}%`;
                    const threatsCount = detectedThreats ? detectedThreats.length : 0;
                    document.getElementById('ai-threats-count').textContent = `${threatsCount} Triggered`;
                    
                    // Display Heuristic AI Verdict
                    document.getElementById('ai-verdict-text').textContent = aiVerdict || 'Analyzing page content...';
                    
                    // Setup Verdict Badge
                    const badge = document.getElementById('ai-verdict-badge');
                    if (badge) {
                        if (contentRiskScore > 60) {
                            badge.textContent = 'DANGER';
                        } else if (contentRiskScore > 30) {
                            badge.textContent = 'SUSPICIOUS';
                        } else {
                            badge.textContent = 'SAFE';
                        }
                    }

                    // Render Threat badges dynamically
                    const badgesContainer = document.getElementById('threat-badges-container');
                    if (badgesContainer) {
                        badgesContainer.innerHTML = '';
                        if (threatsCount === 0) {
                            badgesContainer.innerHTML = '<span class="threat-badge" style="background-color: rgba(16, 185, 129, 0.08); color: #10b981; border-color: rgba(16, 185, 129, 0.25);">✔ No Active Content Threats</span>';
                        } else {
                            detectedThreats.forEach(threat => {
                                const span = document.createElement('span');
                                span.className = 'threat-badge';
                                span.innerHTML = `⚡ ${threat}`;
                                badgesContainer.appendChild(span);
                            });
                        }
                    }
                } else if (aiCard) {
                    aiCard.style.display = 'none';
                }

                // Update Reasons List
                reasonsList.innerHTML = '';
                if (reasons && reasons.length > 0) {
                    reasons.forEach(r => {
                        const li = document.createElement('li');
                        li.textContent = r;
                        reasonsList.appendChild(li);
                    });
                }
            });
        });
    }
});
