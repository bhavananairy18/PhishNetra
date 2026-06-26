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




    function toggleUIState(isEnabled) {
        if (!isEnabled) {
            statusCard.className = 'status-card';
            currentStatus.textContent = 'Disabled';
            currentStatus.style.color = '#64748b';
            riskScore.textContent = '--/100';
            reasonsList.innerHTML = '<li>PhishNetra is currently turned off.</li>';
            if (protectionToggle) protectionToggle.disabled = true;

            // Clear progress blocks
            document.querySelectorAll('.meter-block').forEach(b => b.classList.remove('active'));

            // Clear Website Information
            const domainEl = document.getElementById('info-domain');
            const sslEl = document.getElementById('info-ssl');
            const ageEl = document.getElementById('info-age');
            if (domainEl) domainEl.textContent = '...';
            if (sslEl) sslEl.textContent = '...';
            if (ageEl) ageEl.textContent = '...';
        } else {
            if (protectionToggle) protectionToggle.disabled = false;
            fetchTabInfo();
        }
    }

    function fetchTabInfo() {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs.length === 0) return;
            let urlStr = tabs[0].url;

            if (urlStr.startsWith('chrome-extension://') && (urlStr.includes('warning.html') || urlStr.includes('blocked.html'))) {
                try {
                    const u = new URL(urlStr);
                    const originalUrl = u.searchParams.get('url');
                    if (originalUrl) urlStr = decodeURIComponent(originalUrl);
                } catch(e) {}
            }

            let hostname = 'Unknown';
            let isHttps = false;
            try {
                const url = new URL(urlStr);
                currentDomain.textContent = url.hostname;
                hostname = url.hostname;
                isHttps = (url.protocol === 'https:');
            } catch (e) {
                currentDomain.textContent = 'Extension Page or Blank';
                return;
            }

            chrome.runtime.sendMessage({ type: 'GET_TAB_INFO' }, (response) => {
                if (!response || response.error) {
                    reasonsList.innerHTML = '<li>Unable to analyze this page.</li>';
                    return;
                }

                const { score, reasons, status } = response;

                currentStatus.textContent = status;
                riskScore.textContent = `${score}/100`;

                statusCard.className = 'status-card';
                if (status === 'Safe') statusCard.classList.add('status-safe');
                else if (status === 'Suspicious') statusCard.classList.add('status-suspicious');
                else if (status === 'Dangerous') statusCard.classList.add('status-dangerous');

                // Update 10 segmented progress blocks dynamically
                const activeBlocks = Math.floor(score / 10);
                document.querySelectorAll('.meter-block').forEach((block, idx) => {
                    if (idx < activeBlocks) {
                        block.classList.add('active');
                    } else {
                        block.classList.remove('active');
                    }
                });

                // Update Website Information Card elements dynamically
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
                     ageEl.textContent = 'Loading...';
                     fetchDomainAge(hostname).then(age => {
                         ageEl.textContent = age;
                     });
                 }

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

    function getApexDomain(hostname) {
        const parts = hostname.toLowerCase().split('.');
        if (parts.length <= 2) return hostname;
        
        const commonSLDs = ['com', 'net', 'org', 'co', 'gov', 'edu', 'ac', 'mil', 'or'];
        const lastPart = parts[parts.length - 1];
        const secondLastPart = parts[parts.length - 2];
        
        if (commonSLDs.includes(secondLastPart) && parts.length >= 3) {
            return parts.slice(-3).join('.');
        }
        return parts.slice(-2).join('.');
    }

    async function fetchDomainAge(domain) {
        if (!domain || domain === 'Unknown' || domain === 'Extension Page or Blank') {
            return 'unknown age';
        }
        const apex = getApexDomain(domain);
        try {
            const response = await fetch(`https://rdap.org/domain/${apex}`);
            if (!response.ok) {
                return 'unknown age';
            }
            const data = await response.json();
            
            let registrationDateStr = null;
            if (data.events && Array.isArray(data.events)) {
                for (const event of data.events) {
                    if (event.eventAction === 'registration') {
                        registrationDateStr = event.eventDate;
                        break;
                    }
                }
            }
            
            if (!registrationDateStr) {
                return 'unknown age';
            }

            const registrationDate = new Date(registrationDateStr);
            if (isNaN(registrationDate.getTime())) {
                return 'unknown age';
            }

            const now = new Date();
            const diffTime = now.getTime() - registrationDate.getTime();
            if (diffTime < 0) {
                return 'newly registered';
            }

            const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
            if (diffDays < 30) {
                if (diffDays <= 7) return 'newly registered';
                return `${diffDays} Days`;
            }

            const diffMonths = Math.floor(diffDays / 30.436875);
            if (diffMonths < 12) {
                return `${diffMonths} ${diffMonths === 1 ? 'Month' : 'Months'}`;
            }

            const diffYears = Math.floor(diffMonths / 12);
            const remainingMonths = diffMonths % 12;

            if (remainingMonths === 0) {
                return `${diffYears} ${diffYears === 1 ? 'Year' : 'Years'}`;
            }
            return `${diffYears} ${diffYears === 1 ? 'Year' : 'Years'}, ${remainingMonths} ${remainingMonths === 1 ? 'Month' : 'Months'}`;
        } catch (e) {
            console.error('Error fetching domain age:', e);
            return 'unknown age';
        }
    }
});
