let extensionEnabled = true;
let protectionModeEnabled = true;
let soundAlertsEnabled = true;
let trustedSites = new Set();
let tabScores = new Map(); // tabId -> { score, reasons, status }

// Initialize state from storage
chrome.storage.local.get({
  enabled: true,
  protectionMode: true,
  soundAlerts: true,
  trusted: []
}, (data) => {
  extensionEnabled = data.enabled;
  protectionModeEnabled = data.protectionMode;
  soundAlertsEnabled = data.soundAlerts;
  trustedSites = new Set(data.trusted || []);
});

// Update state on changes
chrome.storage.onChanged.addListener((changes) => {
  if (changes.enabled) extensionEnabled = changes.enabled.newValue;
  if (changes.protectionMode) protectionModeEnabled = changes.protectionMode.newValue;
  if (changes.soundAlerts) soundAlertsEnabled = changes.soundAlerts.newValue;
  if (changes.trusted) trustedSites = new Set(changes.trusted.newValue);
});

// 🔥 MAIN RISK CALCULATION ONLY static details
function calculateRisk(urlStr) {
  let score = 0;
  let reasons = [];
  let status = 'Safe';

  if (!urlStr || urlStr.startsWith('chrome://') || urlStr.startsWith('edge://') || urlStr.startsWith('about:') || urlStr.startsWith('chrome-extension://')) {
    return { score: 0, reasons: [], status: 'Safe', isTrusted: false, isSearchEngine: false };
  }

  try {
    const url = new URL(urlStr);
    const domain = url.hostname.toLowerCase();

    // Whitelist check
    const isTrusted = trustedSites.has(domain);

    // Known search engine check
    const searchEngines = ['google.', 'bing.com', 'yahoo.com', 'duckduckgo.com', 'yandex.', 'ecosia.org', 'search.brave.com'];
    const isSearchEngine = searchEngines.some(se => domain.includes(se));

    if (isSearchEngine) {
      return { score: 0, reasons: ['Known Search Engine.'], status: 'Safe', isTrusted, isSearchEngine: true };
    }

    // 1. Protocol
    if (url.protocol === 'http:') {
      score += 30;
      reasons.push('Connection is not secure (HTTP instead of HTTPS).');
    }

    // 2. Domain structure
    if (url.href.length > 100) {
      score += 15;
      reasons.push('URL length is greater than 100 characters.');
    }

    const domainParts = domain.split('.');
    if (domain.includes('-') || domainParts.length > 3 || (domainParts.length === 3 && domainParts[0] !== 'www')) {
      score += 10;
      reasons.push('Domain contains hyphens or multiple subdomains.');
    }

    const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain) || (/^[a-f0-9:]+$/.test(domain) && domain.includes(':'));
    if (isIP) {
      score += 25;
      reasons.push('Domain is an IP address.');
    }

    // 3. Suspicious keywords
    const specificSuspiciousKeywords = ['login', 'verify', 'bank', 'secure', 'update'];
    if (specificSuspiciousKeywords.some(kw => url.href.toLowerCase().includes(kw))) {
      score += 15;
      reasons.push('URL contains suspicious keywords (login, verify, bank, secure, update).');
    }

    // 6. SSL / trust simulation
    if (domain.includes('badssl') || domain.includes('testpattern')) {
      score += 20;
      reasons.push('Domain contains known bad SSL or test patterns.');
    }

    // Normalize max score to 100
    score = Math.min(score, 100);

    // Determine Status
    if (score <= 30) {
      status = 'Safe';
    } else if (score <= 60) {
      status = 'Suspicious';
    } else {
      status = 'Dangerous';
    }

    if (isTrusted) {
      reasons.push('Site is explicitly trusted by the user.');
    }

    return { score, reasons, status, isTrusted, isSearchEngine: false };

  } catch (e) {
    return { score: 0, reasons: ['Invalid URL format.'], status: 'Safe', isTrusted: false, isSearchEngine: false };
  }
}

// Redirect utility
function routeTab(tabId, url, data) {
  let targetHtml = '';
  if (data.status === 'Dangerous') {
    targetHtml = 'blocked.html';
  } else if (data.status === 'Suspicious') {
    targetHtml = 'warning.html';
  }

  if (targetHtml !== '') {
    const redirectUrl = chrome.runtime.getURL(targetHtml)
      + `?url=${encodeURIComponent(url)}`
      + `&score=${data.score}`
      + `&reasons=${encodeURIComponent(JSON.stringify(data.reasons))}`;

    chrome.tabs.update(tabId, { url: redirectUrl });
  }
}

// Ensure the popup can access scores
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_TAB_INFO') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || tabs.length === 0) {
        sendResponse({ error: 'No active tab' });
        return;
      }
      const tabId = tabs[0].id;
      let targetUrl = tabs[0].url;
      // FIRST, check if we are on a warning or blocked page. 
      // ALWAYS pull data from URL if we are, because they represent the TRUE blocked state.
      let isWarningOrBlocked = targetUrl.startsWith('chrome-extension://') && (targetUrl.includes('warning.html') || targetUrl.includes('blocked.html'));

      let data = null;

      if (isWarningOrBlocked) {
        try {
          const urlObj = new URL(targetUrl);
          const originalUrl = urlObj.searchParams.get('url');
          const urlScore = parseInt(urlObj.searchParams.get('score'));

          const urlReasonsStr = urlObj.searchParams.get('reasons');
          let urlReasons = [];
          if (urlReasonsStr) {
            try { urlReasons = JSON.parse(urlReasonsStr); } catch (e) { }
          }

          if (originalUrl && !isNaN(urlScore)) {
            let status = 'Safe';
            if (urlScore >= 31 && urlScore <= 60) status = 'Suspicious';
            else if (urlScore >= 61) status = 'Dangerous';

            data = { score: urlScore, reasons: urlReasons, status, isTrusted: false, isSearchEngine: false };
          }
        } catch (e) { }
      }

      // If not on warning page, or parsing failed, fallback to memory or active calculation
      if (!data) {
        data = tabScores.get(tabId) || calculateRisk(targetUrl);
      }

      sendResponse(data);
    });
    return true; // async
  }

  if (message.type === 'TRUST_SITE') {
    const domain = message.domain;
    trustedSites.add(domain);
    chrome.storage.local.set({ trusted: Array.from(trustedSites) }, () => {
      sendResponse({ success: true });
    });
    return true; // async
  }

  if (message.type === 'CALCULATE_RISK') {
    sendResponse(calculateRisk(message.url));
  }

  if (message.type === 'ANALYZE_PAGE_CONTENT') {
    const { hasPassword, hasCC, hasOTP, hasExternalForm, hasHiddenFields, hasSuspiciousIframe, url } = message;
    const tabId = sender.tab ? sender.tab.id : message.tabId;

    if (extensionEnabled) {
      let data = calculateRisk(url); // ALWAYS start from fresh static risk
      let contentScoreAdded = 0;

      // 4 & 5. Forms, inputs, and hidden elements
      if (hasPassword) {
        contentScoreAdded += 20;
        data.reasons.push('Password field exists.');
      }
      if (hasCC) {
        contentScoreAdded += 25;
        data.reasons.push('Credit card related fields detected.');
      }
      if (hasOTP) {
        contentScoreAdded += 15;
        data.reasons.push('OTP or verification fields detected.');
      }
      if (hasExternalForm) {
        contentScoreAdded += 20;
        data.reasons.push('Form submits to a different domain.');
      }
      if (hasHiddenFields) {
        contentScoreAdded += 20;
        data.reasons.push('Hidden password fields detected.');
      }
      if (hasSuspiciousIframe) {
        contentScoreAdded += 15;
        data.reasons.push('Invisible iframes detected.');
      }

      if (contentScoreAdded > 0) {
        data.score = Math.min(100, data.score + contentScoreAdded);
        if (data.score <= 30) data.status = 'Safe';
        else if (data.score <= 60) data.status = 'Suspicious';
        else data.status = 'Dangerous';
      }

      tabScores.set(tabId, data);

      if (protectionModeEnabled && !data.isTrusted && (data.status === 'Dangerous' || data.status === 'Suspicious')) {
        routeTab(tabId, url, data);
      }

      sendResponse({ status: data.status, score: data.score, protectionModeEnabled, soundAlertsEnabled, isSearchEngine: data.isSearchEngine });
    } else {
      sendResponse({ status: 'Disabled', score: 0 });
    }
  }
});

// Intercept navigation before fully loading (The early interception is back to working!)
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0 || !extensionEnabled) return; // Main frame only
  if (details.url.startsWith('chrome-extension://')) return; // ignore our own pages

  const result = calculateRisk(details.url);
  tabScores.set(details.tabId, result);

  if (protectionModeEnabled && !result.isTrusted && (result.status === 'Dangerous' || result.status === 'Suspicious')) {
    routeTab(details.tabId, details.url, result);
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    if (changeInfo.url.startsWith('chrome-extension://')) return;
    const result = calculateRisk(changeInfo.url);
    tabScores.set(tabId, result);

    if (protectionModeEnabled && !result.isTrusted && (result.status === 'Dangerous' || result.status === 'Suspicious')) {
      routeTab(tabId, changeInfo.url, result);
    }
  }

  if (changeInfo.status === 'complete' && tab.url && !tab.url.startsWith('chrome')) {
    // Only calculate, without history logging
    const result = tabScores.get(tabId) || calculateRisk(tab.url);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabScores.delete(tabId);
});