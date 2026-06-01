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
        if (!isEnabled) {
            statusCard.className = 'status-card';
            currentStatus.textContent = 'Disabled';
            currentStatus.style.color = '#64748b';
            riskScore.textContent = '--/100';
            reasonsList.innerHTML = '<li>PhishNetra is currently turned off.</li>';
            protectionToggle.disabled = true;
        } else {
            protectionToggle.disabled = false;
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

            try {
                const url = new URL(urlStr);
                currentDomain.textContent = url.hostname;
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
