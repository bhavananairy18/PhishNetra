document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url');
    const score = urlParams.get('score');

    let reasons = [];
    try {
        reasons = JSON.parse(decodeURIComponent(urlParams.get('reasons') || '[]'));
    } catch (e) {
        console.error('Could not parse reasons', e);
    }

    // Populate data
    if (score) {
        document.getElementById('risk-score').textContent = `${score}/100`;
    }

    const reasonsList = document.getElementById('reasons-list');
    if (reasons && reasons.length > 0) {
        reasons.forEach(r => {
            const li = document.createElement('li');
            li.textContent = r;
            reasonsList.appendChild(li);
        });
    } else {
        reasonsList.innerHTML = '<li>Analyzing page attributes...</li>';
    }

    // Button actions
    document.getElementById('btn-back').addEventListener('click', () => {
        // Go to history back if possible, else close tab
        if (window.history.length > 1) {
            window.history.back();
        } else {
            chrome.tabs.getCurrent(tab => {
                if (tab) {
                    chrome.tabs.remove(tab.id);
                } else {
                    window.close();
                }
            });
        }
    });
});

