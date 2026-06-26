// PhishNetra Content Script
// Runs at document_start

let hasAnalyzedForms = false;

// Analyze forms once DOM is somewhat interactive
document.addEventListener('DOMContentLoaded', () => {
    checkForSensitiveFields();
});

// Also use mutation observer in case forms are loaded dynamically
const observer = new MutationObserver(() => {
    if (!hasAnalyzedForms) {
        checkForSensitiveFields();
    }
});
observer.observe(document, { childList: true, subtree: true });

function getApexDomainLocal(hostname) {
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

function scanPageText() {
    const text = document.body ? document.body.innerText : '';
    const urgencyPatterns = [
        /account\s+(suspended|locked|blocked|disabled|restricted)/i,
        /action\s+required/i,
        /verify\s+(your\s+)?identity/i,
        /immediate\s+attention/i,
        /unusual\s+activity/i,
        /security\s+(alert|breach|update)/i,
        /log\s+in\s+(now|immediately|to\s+verify)/i,
        /unauthorized\s+access/i,
        /confirm\s+password/i,
        /update\s+your\s+billing/i,
        /avoid\s+fees/i,
        /suspended\s+temporarily/i,
        /verify\s+your\s+account/i,
        /urgent\s+security\s+notice/i
    ];

    const scamPatterns = [
        /claim\s+(reward|prize|refund|cash|gift)/i,
        /lottery\s+winner/i,
        /invest\s+now/i,
        /double\s+your/i,
        /secret\s+formula/i,
        /risk-free\s+trial/i
    ];

    const sensitivePatterns = [
        /enter\s+(your\s+)?(password|pin|otp|passcode|cvv|social\s+security|ssn)/i,
        /credit\s+card\s+number/i,
        /bank\s+routing\s+number/i,
        /card\s+expiration/i
    ];

    let fakeUrgencyCount = 0;
    let fakeUrgencyDetails = [];
    let sensitiveKeywordsFound = [];

    urgencyPatterns.forEach(pattern => {
        const matches = text.match(pattern);
        if (matches) {
            fakeUrgencyCount++;
            fakeUrgencyDetails.push(matches[0]);
        }
    });

    scamPatterns.forEach(pattern => {
        const matches = text.match(pattern);
        if (matches) {
            fakeUrgencyCount++;
            fakeUrgencyDetails.push(matches[0]);
        }
    });

    sensitivePatterns.forEach(pattern => {
        const matches = text.match(pattern);
        if (matches) {
            sensitiveKeywordsFound.push(matches[0]);
        }
    });

    return { fakeUrgencyCount, fakeUrgencyDetails, sensitiveKeywordsFound };
}

function scanMismatchedLinks() {
    const links = document.querySelectorAll('a');
    let mismatchedLinksCount = 0;
    let mismatchedLinksDetails = [];
    let totalLinksCount = links.length;
    let externalLinksCount = 0;
    
    const ssoWhitelist = [
        'google.com', 'facebook.com', 'apple.com', 'microsoft.com', 
        'twitter.com', 'linkedin.com', 'github.com', 'okta.com', 
        'auth0.com', 'amazon.com', 'salesforce.com'
    ];

    const hostApex = getApexDomainLocal(window.location.hostname);

    links.forEach(link => {
        const href = (link.href || '').trim();
        const text = (link.innerText || '').trim();
        
        if (!href || !href.startsWith('http')) return;

        let hrefUrl;
        try {
            hrefUrl = new URL(href);
        } catch (e) {
            return;
        }

        const hrefHostname = hrefUrl.hostname.toLowerCase();
        const linkApex = getApexDomainLocal(hrefHostname);

        if (linkApex !== hostApex) {
            externalLinksCount++;
        }
        
        // 1. Text looks like a URL/domain, but href goes to a different domain
        const domainRegex = /^(https?:\/\/)?(www\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/\S*)?$/;
        
        if (domainRegex.test(text)) {
            let textDomain = text.toLowerCase();
            if (textDomain.startsWith('http://')) textDomain = textDomain.substring(7);
            if (textDomain.startsWith('https://')) textDomain = textDomain.substring(8);
            if (textDomain.startsWith('www.')) textDomain = textDomain.substring(4);
            textDomain = textDomain.split('/')[0];

            const cleanHrefHost = hrefHostname.replace(/^www\./, '');
            const cleanTextDomain = textDomain.replace(/^www\./, '');

            if (cleanTextDomain !== cleanHrefHost && !ssoWhitelist.some(sso => cleanHrefHost.includes(sso))) {
                mismatchedLinksCount++;
                mismatchedLinksDetails.push({ text: text, href: href });
            }
        } else {
            // 2. Text claims a brand but links to an unrelated external domain
            const brandNames = ['paypal', 'netflix', 'google', 'microsoft', 'bankofamerica', 'chase', 'wells fargo', 'facebook', 'instagram', 'amazon'];
            const lowerText = text.toLowerCase();
            
            if (linkApex !== hostApex) {
                const mentionsBrand = brandNames.some(brand => lowerText.includes(brand));
                const matchedBrand = brandNames.find(brand => lowerText.includes(brand));
                
                if (mentionsBrand && matchedBrand && !linkApex.includes(matchedBrand) && 
                    !ssoWhitelist.some(sso => linkApex.includes(sso))) {
                    mismatchedLinksCount++;
                    mismatchedLinksDetails.push({ text: text, href: href });
                }
            }
        }
    });

    return { mismatchedLinksCount, mismatchedLinksDetails, totalLinksCount, externalLinksCount };
}

function scanButtonsAndPopups() {
    let highRiskButtonsCount = 0;
    let highRiskButtons = [];
    let popupDetected = false;

    const buttons = document.querySelectorAll('button, input[type="submit"], input[type="button"], a.btn, a.button');
    const highRiskCTAs = [
        /verify\s+(now|account|identity)/i,
        /claim\s+(refund|reward|prize)/i,
        /unlock\s+(account|profile)/i,
        /access\s+funds/i,
        /secure\s+(login|account)/i,
        /resolve\s+issue/i,
        /update\s+(billing|payment|details)/i
    ];

    buttons.forEach(btn => {
        const text = (btn.innerText || btn.value || '').trim();
        highRiskCTAs.forEach(regex => {
            if (regex.test(text)) {
                highRiskButtonsCount++;
                highRiskButtons.push(text);
            }
        });
    });

    const divs = document.querySelectorAll('div, section');
    divs.forEach(el => {
        try {
            const style = window.getComputedStyle(el);
            if ((style.position === 'fixed' || style.position === 'absolute') && 
                style.display !== 'none' && style.visibility !== 'hidden') {
                const zIndex = parseInt(style.zIndex);
                if (!isNaN(zIndex) && zIndex > 100) {
                    const innerText = (el.innerText || '').toLowerCase();
                    const hasInputs = el.querySelectorAll('input').length > 0;
                    if (hasInputs && (innerText.includes('verify') || innerText.includes('suspend') || innerText.includes('action required') || innerText.includes('login') || innerText.includes('password'))) {
                        popupDetected = true;
                    }
                }
            }
        } catch (e) {}
    });

    return { highRiskButtonsCount, highRiskButtons, popupDetected };
}

function checkForSensitiveFields() {
    const inputs = document.querySelectorAll('input');
    let hasPassword = false;
    let hasCC = false;
    let hasOTP = false;
    let hasHiddenFields = false;

    inputs.forEach(input => {
        const type = input.type.toLowerCase();
        const name = (input.name || '').toLowerCase();
        const id = (input.id || '').toLowerCase();

        if (type === 'password') hasPassword = true;
        if (name.includes('card') || id.includes('card') || name.includes('cc') || id.includes('cc')) hasCC = true;
        if (name.includes('otp') || id.includes('otp') || name.includes('code') || id.includes('code') || type === 'number' && name.includes('verify')) hasOTP = true;

        // Check for hidden sensitive fields
        try {
            const style = window.getComputedStyle(input);
            if ((style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0' || type === 'hidden') && (type === 'password' || name.includes('password'))) {
                hasHiddenFields = true;
            }
        } catch(e) {}
    });

    const forms = document.querySelectorAll('form');
    let hasLoginForm = forms.length > 0;
    let hasExternalForm = false;

    forms.forEach(f => {
        if (f.action && f.action.startsWith('http')) {
            try {
                const actionUrl = new URL(f.action);
                if (actionUrl.hostname !== window.location.hostname) {
                    hasExternalForm = true;
                }
            } catch (e) { }
        }
    });

    let hasSuspiciousIframe = false;
    document.querySelectorAll('iframe').forEach(ifr => {
        if (ifr.width === '0' || ifr.height === '0' || ifr.style.display === 'none') {
            hasSuspiciousIframe = true;
        }
    });

    // Run advanced content scans
    const textScan = scanPageText();
    const linkScan = scanMismatchedLinks();
    const elementScan = scanButtonsAndPopups();

    // Trigger analysis unconditionally so that visual features are ALWAYS sent and popup stays up to date
    hasAnalyzedForms = true;

    chrome.runtime.sendMessage({
        type: 'ANALYZE_PAGE_CONTENT',
        hasPassword,
        hasCC,
        hasOTP,
        hasExternalForm,
        hasHiddenFields,
        hasSuspiciousIframe,
        mismatchedLinksCount: linkScan.mismatchedLinksCount,
        mismatchedLinksDetails: linkScan.mismatchedLinksDetails,
        fakeUrgencyCount: textScan.fakeUrgencyCount,
        fakeUrgencyDetails: textScan.fakeUrgencyDetails,
        sensitiveKeywordsFound: textScan.sensitiveKeywordsFound,
        highRiskButtonsCount: elementScan.highRiskButtonsCount,
        highRiskButtons: elementScan.highRiskButtons,
        popupDetected: elementScan.popupDetected,
        totalLinksCount: linkScan.totalLinksCount,
        externalLinksCount: linkScan.externalLinksCount,
        url: window.location.href,
        tabId: null
    }, (response) => {
        if (!response) return;

        const { status, protectionModeEnabled, soundAlertsEnabled } = response;

        if (status === 'Dangerous') {
            if (soundAlertsEnabled) playWarningSound();
        }

        if (status === 'Suspicious') {
            showBanner('Suspicious site detected! Think twice before entering sensitive info.');
        } else if (status === 'Dangerous') {
            if (!protectionModeEnabled) {
                showBanner('DANGER: This website is highly unsafe. Leaving is recommended.', true);
            } else {
                showFullPageBlock();
            }
        }
    });
}
let soundPlayedThisSession = false;

function playWarningSound() {
    if (soundPlayedThisSession) return;

    const playAudio = () => {
        if (soundPlayedThisSession) return;
        try {
            const audio = new Audio(chrome.runtime.getURL('sound.mpeg'));
            audio.play()
                .then(() => {
                    soundPlayedThisSession = true;
                    removeListeners();
                })
                .catch(e => {
                    console.log('Audio playback deferred (waiting for interaction).');
                });
        } catch (e) {
            console.warn('Audio tag playback not supported:', e);
        }
    };

    const removeListeners = () => {
        document.removeEventListener('click', playAudio);
        document.removeEventListener('keydown', playAudio);
    };

    // Try playing immediately
    try {
        const audio = new Audio(chrome.runtime.getURL('sound.mpeg'));
        audio.play()
            .then(() => {
                soundPlayedThisSession = true;
            })
            .catch(e => {
                console.log('Immediate audio playback blocked by browser, waiting for user interaction.');
                document.addEventListener('click', playAudio);
                document.addEventListener('keydown', playAudio);
            });
    } catch (e) {
        console.warn('Audio playback error:', e);
    }
}

function showBanner(message, isDanger = false) {
    // Don't show multiple banners
    if (document.getElementById('PhishNetra-banner')) return;

    const banner = document.createElement('div');
    banner.id = 'PhishNetra-banner';
    banner.className = `PhishNetra-banner ${isDanger ? 'PhishNetra-danger' : 'PhishNetra-warning'}`;

    banner.innerHTML = `
    <div class="PhishNetra-banner-content">
      <span class="PhishNetra-icon">${isDanger ? 'ðŸš¨' : 'âš ï¸'}</span>
      <span class="PhishNetra-text"><strong>PhishNetra:</strong> ${message}</span>
    </div>
    <button class="PhishNetra-close" id="PhishNetra-close-btn">&times;</button>
  `;

    document.body.prepend(banner);

    document.getElementById('PhishNetra-close-btn').addEventListener('click', () => {
        banner.remove();
    });
}

function showFullPageBlock() {
    if (document.getElementById('PhishNetra-overlay')) return;

    const overlay = document.createElement('div');
    overlay.id = 'PhishNetra-overlay';
    overlay.innerHTML = `
    <div class="PhishNetra-overlay-box">
      <h1>🚨 Access Blocked by PhishNetra</h1>
      <p>This website is dangerous and may steal your data.</p>
      <p>Forms requesting sensitive information were found.</p>
    </div>
  `;
    document.body.appendChild(overlay);
    document.body.style.overflow = 'hidden';
}

let currentLinkBanner = null;
let keepLinkBannerVisible = false;
let linkBannerFadeoutTimeout = null;

function showLinkTooltip(element, score, status) {
    if (element.hasAttribute('data-phishnetra-tooltip')) return;
    element.setAttribute('data-phishnetra-tooltip', 'true');
    
    if (linkBannerFadeoutTimeout) {
        clearTimeout(linkBannerFadeoutTimeout);
        linkBannerFadeoutTimeout = null;
    }
    
    if (!currentLinkBanner) {
        currentLinkBanner = document.createElement('div');
        document.body.appendChild(currentLinkBanner);
    }
    
    keepLinkBannerVisible = false;
    currentLinkBanner.style.opacity = '1';
    currentLinkBanner.style.transition = 'opacity 0.3s ease';
    
    let color = '#10b981'; // safe
    let label = 'SAFE';
    
    if (score > 60) {
        color = '#ef4444'; // danger
        label = 'DANGER';
    } else if (score > 30) {
        color = '#f59e0b'; // suspicious
        label = 'SUSPICIOUS';
    }
    
    currentLinkBanner.style.position = 'fixed';
    currentLinkBanner.style.top = '12px';
    currentLinkBanner.style.left = '50%';
    currentLinkBanner.style.transform = 'translateX(-50%)';
    currentLinkBanner.style.backgroundColor = '#18181b';
    currentLinkBanner.style.color = '#fff';
    currentLinkBanner.style.border = `1px solid ${color}`;
    currentLinkBanner.style.padding = '8px 16px';
    currentLinkBanner.style.borderRadius = '24px';
    currentLinkBanner.style.fontFamily = 'system-ui, -apple-system, sans-serif';
    currentLinkBanner.style.fontSize = '14px';
    currentLinkBanner.style.fontWeight = '600';
    currentLinkBanner.style.zIndex = '2147483647';
    currentLinkBanner.style.pointerEvents = 'none';
    currentLinkBanner.style.boxShadow = `0 4px 12px rgba(0, 0, 0, 0.4), 0 0 8px ${color}40`;
    currentLinkBanner.style.display = 'flex';
    currentLinkBanner.style.alignItems = 'center';
    currentLinkBanner.style.justifyContent = 'center';
    
    if (score > 60) {
        currentLinkBanner.innerHTML = `
            <span style="font-size: 18px; margin-right: 8px;">⚠️</span>
            <span>Risk: ${score}/100 &mdash; <span style="color: ${color};">${label}</span></span>
        `;
    } else {
        currentLinkBanner.innerHTML = `
            <span>Risk: ${score}/100 &mdash; <span style="color: ${color};">${label}</span></span>
        `;
    }

    const clickHandler = () => {
        keepLinkBannerVisible = true;
        if (currentLinkBanner) currentLinkBanner.style.opacity = '1';
        if (linkBannerFadeoutTimeout) clearTimeout(linkBannerFadeoutTimeout);
        linkBannerFadeoutTimeout = setTimeout(() => {
            if (currentLinkBanner) {
                currentLinkBanner.style.opacity = '0';
                keepLinkBannerVisible = false;
            }
        }, 3500);
    };

    const mouseLeaveHandler = () => {
        if (!keepLinkBannerVisible && currentLinkBanner) {
            currentLinkBanner.style.opacity = '0';
        }
        element.removeAttribute('data-phishnetra-tooltip');
        element.removeEventListener('click', clickHandler);
    };
    
    element.addEventListener('mouseleave', mouseLeaveHandler, { once: true });
    element.addEventListener('click', clickHandler);
}

document.addEventListener('mouseover', (e) => {
    const a = e.target.closest('a');
    if (a && a.href && a.href.startsWith('http')) {
        chrome.runtime.sendMessage({ type: 'CALCULATE_RISK', url: a.href }, (response) => {
            if (response && response.score !== undefined) {
                showLinkTooltip(a, response.score, response.status);
            }
        });
    }
});

function showAutoAlert(status, score) {
    if (document.getElementById('phishnetra-auto-alert')) return;
    if (status === 'Disabled') return;

    const alertBox = document.createElement('div');
    alertBox.id = 'phishnetra-auto-alert';
    
    let color = '#10b981'; // safe
    let label = 'SAFE';
    
    if (score > 60) {
        color = '#ef4444'; // danger
        label = 'DANGER';
    } else if (score > 30) {
        color = '#f59e0b'; // suspicious
        label = 'SUSPICIOUS';
    }

    alertBox.style.position = 'fixed';
    alertBox.style.top = '50%';
    alertBox.style.left = '50%';
    alertBox.style.transform = 'translate(-50%, -50%)';
    alertBox.style.backgroundColor = '#18181b';
    alertBox.style.color = '#fff';
    alertBox.style.border = `1px solid ${color}`;
    alertBox.style.padding = '16px 32px';
    alertBox.style.borderRadius = '32px';
    alertBox.style.fontFamily = 'system-ui, -apple-system, sans-serif';
    alertBox.style.fontSize = '18px';
    alertBox.style.fontWeight = '600';
    alertBox.style.zIndex = '2147483647';
    alertBox.style.pointerEvents = 'none';
    alertBox.style.boxShadow = `0 8px 24px rgba(0, 0, 0, 0.6), 0 0 12px ${color}60`;
    alertBox.style.display = 'flex';
    alertBox.style.alignItems = 'center';
    alertBox.style.justifyContent = 'center';
    alertBox.style.opacity = '0';
    alertBox.style.transition = 'opacity 0.5s ease';

    if (score > 60) {
        alertBox.innerHTML = `
            <span style="font-size: 24px; margin-right: 12px;">⚠️</span>
            <span>Site Risk: ${score}/100 &mdash; <span style="color: ${color};">${label}</span></span>
        `;
    } else {
        alertBox.innerHTML = `
            <span>Site Risk: ${score}/100 &mdash; <span style="color: ${color};">${label}</span></span>
        `;
    }

    document.body.appendChild(alertBox);
    
    setTimeout(() => {
        alertBox.style.opacity = '1';
    }, 10);

    setTimeout(() => {
        if (alertBox.parentElement) {
            alertBox.style.opacity = '0';
            setTimeout(() => alertBox.remove(), 500); // fade out effect
        }
    }, 3500);
}

// Initial check on load (for static sites)
chrome.runtime.sendMessage({
    type: 'ANALYZE_PAGE_CONTENT',
    hasPassword: false,
    hasCC: false,
    hasOTP: false,
    hasExternalForm: false,
    hasHiddenFields: false,
    hasSuspiciousIframe: false,
    url: window.location.href
}, (response) => {
    if (!response) return;

    const runChecks = () => {
        showAutoAlert(response.status, response.score);

        if (response.status === 'Dangerous' && response.soundAlertsEnabled) {
            playWarningSound();
        }

        if (response.status === 'Suspicious') {
            showBanner('Suspicious site detected! Exercise caution.');
        } else if (response.status === 'Dangerous' && !response.protectionModeEnabled) {
            showBanner('DANGER: This website is highly unsafe. Leaving is recommended.', true);
        }
    };

    if (document.readyState === 'interactive' || document.readyState === 'complete' || document.body) {
        runChecks();
    } else {
        document.addEventListener('DOMContentLoaded', runChecks);
    }
});
// ✅ FIX: Run analysis again after full page load
window.addEventListener("load", () => {
    setTimeout(() => {
        hasAnalyzedForms = false; // allow re-evaluating filled forms
        checkForSensitiveFields();
    }, 2000);
});
