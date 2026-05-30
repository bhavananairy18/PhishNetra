document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url');
    const score = urlParams.get('score');
    let reasons = [];
    
    try {
        reasons = JSON.parse(decodeURIComponent(urlParams.get('reasons') || '[]'));
    } catch (e) {
        console.error('Failed to parse reasons:', e);
    }
    
    document.getElementById('url-display').textContent = targetUrl || 'Unknown URL';
    document.getElementById('score-display').textContent = score || '--';
    
    const reasonsList = document.getElementById('reasons-list');
    if (reasons.length > 0) {
        reasonsList.innerHTML = '';
        reasons.forEach(r => {
            const li = document.createElement('li');
            li.textContent = r;
            reasonsList.appendChild(li);
        });
    }
    
    document.getElementById('deny-btn').addEventListener('click', () => {
        // Go back or close tab
        if (window.history.length > 1) {
            window.history.back();
        } else {
            // Can't close window unconditionally without user interaction in some cases, but works for tabs
            chrome.tabs.getCurrent((tab) => {
                if (tab) {
                    chrome.tabs.remove(tab.id);
                } else {
                    window.close();
                }
            });
        }
    });
    
    document.getElementById('continue-btn').addEventListener('click', () => {
        if (!targetUrl) return;
        
        // Trust the site temporarily or permanently so background.js doesn't block it again
        const domain = new URL(targetUrl).hostname;
        
        chrome.runtime.sendMessage({
            type: 'TRUST_SITE',
            domain: domain
        }, () => {
            window.location.href = targetUrl;
        });
    });
});
