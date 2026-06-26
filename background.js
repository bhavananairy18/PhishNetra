let extensionEnabled = true;
let protectionModeEnabled = true;
let soundAlertsEnabled = true;
let trustedSites = new Set();
let tabScores = new Map(); // tabId -> { score, reasons, status }
let pendingInfoRequests = new Map(); // tabId -> Array of resolver functions

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

// Apex domain extraction helper
function getApexDomain(hostname) {
  if (!hostname || hostname === 'Unknown' || hostname === 'Extension Page or Blank') {
    return null;
  }
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

// Fetch and cache domain age
async function fetchAndCacheDomainAge(hostname) {
  const apex = getApexDomain(hostname);
  if (!apex) return 'age unavailable';

  return new Promise((resolve) => {
    chrome.storage.local.get(['domainAgeCache'], async (data) => {
      let cache = data.domainAgeCache || {};
      const now = Date.now();
      
      // If cached and not expired (7 days = 604800000 ms)
      if (cache[apex] && (now - cache[apex].timestamp < 604800000)) {
        resolve(cache[apex].age);
        return;
      }
      
      try {
        const response = await fetch(`https://rdap.org/domain/${apex}`);
        if (!response.ok) {
          throw new Error('RDAP fetch failed');
        }
        const rdapData = await response.json();
        
        let registrationDateStr = null;
        if (rdapData.events && Array.isArray(rdapData.events)) {
            for (const event of rdapData.events) {
                if (event.eventAction === 'registration') {
                    registrationDateStr = event.eventDate;
                    break;
                }
            }
        }
        
        if (!registrationDateStr) {
            throw new Error('No registration date');
        }

        const registrationDate = new Date(registrationDateStr);
        if (isNaN(registrationDate.getTime())) {
            throw new Error('Invalid registration date');
        }

        const diffTime = now - registrationDate.getTime();
        let ageResult = 'age unavailable';
        
        if (diffTime < 0) {
            ageResult = 'newly registered';
        } else {
            const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
            if (diffDays < 30) {
                ageResult = diffDays <= 7 ? 'newly registered' : `${diffDays} Days`;
            } else {
                const diffMonths = Math.floor(diffDays / 30.436875);
                if (diffMonths < 12) {
                    ageResult = `${diffMonths} ${diffMonths === 1 ? 'Month' : 'Months'}`;
                } else {
                    const diffYears = Math.floor(diffMonths / 12);
                    const remainingMonths = diffMonths % 12;
                    if (remainingMonths === 0) {
                        ageResult = `${diffYears} ${diffYears === 1 ? 'Year' : 'Years'}`;
                    } else {
                        ageResult = `${diffYears} ${diffYears === 1 ? 'Year' : 'Years'}, ${remainingMonths} ${remainingMonths === 1 ? 'Month' : 'Months'}`;
                    }
                }
            }
        }

        // Save to cache
        cache[apex] = { age: ageResult, timestamp: now };
        chrome.storage.local.set({ domainAgeCache: cache });
        resolve(ageResult);

      } catch (e) {
        console.error('Error prefetching domain age:', e);
        // Save 'age unavailable' in cache temporarily (e.g. 1 hour) so we don't spam failed queries
        cache[apex] = { age: 'age unavailable', timestamp: now - 604800000 + 3600000 };
        chrome.storage.local.set({ domainAgeCache: cache });
        resolve('age unavailable');
      }
    });
  });
}

// 🔥 MAIN RISK CALCULATION ONLY static details
function calculateRisk(urlStr) {
  const res = calculateRiskScore(urlStr);
  return {
    score: res.score,
    reasons: res.reasons,
    status: res.status,
    isTrusted: res.isTrusted,
    isSearchEngine: res.isSearchEngine
  };
}

// Unified Risk Calculation
function calculateRiskScore(urlStr, contentData = null) {
  let score = 0;
  let reasons = [];
  let status = 'Safe';
  let isTrusted = false;
  let isSearchEngine = false;

  if (!urlStr || urlStr.startsWith('chrome://') || urlStr.startsWith('edge://') || urlStr.startsWith('about:') || urlStr.startsWith('chrome-extension://')) {
    return { 
      score: 0, 
      reasons: [], 
      status: 'Safe', 
      isTrusted: false, 
      isSearchEngine: false,
      contentRiskScore: 0,
      aiVerdict: "SAFE: No deceptive text, mismatched links, or unauthorized sensitive forms were detected on this page.",
      detectedThreats: []
    };
  }

  try {
    const url = new URL(urlStr);
    const domain = url.hostname.toLowerCase();

    // Whitelist check
    isTrusted = trustedSites.has(domain);

    // Known search engine check
    const searchEngines = ['google.', 'bing.com', 'yahoo.com', 'duckduckgo.com', 'yandex.', 'ecosia.org', 'search.brave.com'];
    isSearchEngine = searchEngines.some(se => domain.includes(se));

    if (isSearchEngine) {
      return { 
        score: 0, 
        reasons: ['Known Search Engine.'], 
        status: 'Safe', 
        isTrusted, 
        isSearchEngine: true,
        contentRiskScore: 0,
        aiVerdict: "SAFE: No deceptive text, mismatched links, or unauthorized sensitive forms were detected on this page.",
        detectedThreats: []
      };
    }

    // 1. Protocol
    if (url.protocol === 'http:') {
      score += 30;
      reasons.push('Connection is not secure (HTTP instead of HTTPS).');
    }

    // 2. Domain structure
    if (url.href.length > 25) {
      score += 15;
      reasons.push('URL length is greater than 25 characters.');
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
    let staticScore = Math.min(score, 100);

    // Content checks
    let contentRiskScore = 0;
    let contentReasons = [];
    let detectedThreats = [];
    let aiVerdict = "SAFE: No deceptive text, mismatched links, or unauthorized sensitive forms were detected on this page.";

    if (contentData) {
      const { 
        hasPassword, hasCC, hasOTP, hasExternalForm, hasHiddenFields, hasSuspiciousIframe,
        mismatchedLinksCount, fakeUrgencyCount, sensitiveKeywordsFound, highRiskButtonsCount, popupDetected
      } = contentData;

      // Mismatched links (+35 each, max 40)
      if (mismatchedLinksCount > 0) {
        contentRiskScore += Math.min(40, mismatchedLinksCount * 35);
        contentReasons.push(`Deceptive mismatched links detected (${mismatchedLinksCount} found).`);
        detectedThreats.push("Deceptive Mismatched Links");
      }

      // Fake Urgency NLP patterns (+15 each, max 30)
      if (fakeUrgencyCount > 0) {
        contentRiskScore += Math.min(30, fakeUrgencyCount * 15);
        contentReasons.push(`Fake urgency or phishing text detected (${fakeUrgencyCount} triggers).`);
        detectedThreats.push("High-Urgency Threat Copy");
      }

      // Sensitive requests in text (+20, max 25)
      if (sensitiveKeywordsFound && sensitiveKeywordsFound.length > 0) {
        contentRiskScore += 20;
        contentReasons.push(`Requests for sensitive credentials or security info found in text.`);
        detectedThreats.push("Credential Harvesting Signals");
      }

      // Inputs: passwords (+20), credit cards (+25), OTPs (+15). Max 25 (if combined, max 25 content inputs score)
      let inputScore = 0;
      if (hasPassword) {
        inputScore += 20;
        contentReasons.push("Password input field detected.");
      }
      if (hasCC) {
        inputScore += 25;
        contentReasons.push("Billing or credit card fields detected.");
      }
      if (hasOTP) {
        inputScore += 15;
        contentReasons.push("Security OTP/Verification code fields detected.");
      }
      if (inputScore > 0) {
        contentRiskScore += Math.min(25, inputScore);
      }

      // External form actions when sensitive inputs exist (+30)
      if (hasExternalForm && (hasPassword || hasCC || hasOTP)) {
        contentRiskScore += 30;
        contentReasons.push("Secure login form submits to an external untrusted domain.");
        detectedThreats.push("External Credential Submission");
      } else if (hasExternalForm) {
        contentRiskScore += 15;
        contentReasons.push("Form submits to a different domain.");
      }

      // Hidden sensitive inputs or suspicious iframes (+15)
      if (hasHiddenFields) {
        contentRiskScore += 15;
        contentReasons.push("Hidden sensitive inputs detected.");
      }
      if (hasSuspiciousIframe) {
        contentRiskScore += 15;
        contentReasons.push("Invisible or suspicious iframes detected.");
      }

      // Popups or high-risk buttons requesting credentials (+15)
      if (popupDetected) {
        contentRiskScore += 15;
        contentReasons.push("Suspicious overlay login popup detected.");
        detectedThreats.push("Deceptive Popup Overlays");
      }
      if (highRiskButtonsCount > 0) {
        contentRiskScore += 10;
        contentReasons.push("Urgent Action buttons found on page.");
      }

      contentRiskScore = Math.min(100, contentRiskScore);

      // Heuristic AI Verdict Generator
      if (contentRiskScore > 60) {
        aiVerdict = "DANGEROUS: Deceptive content detected. Highly suspicious urgency messages combined with mismatched/deceptive links and input fields requesting sensitive details (credentials/billing). This is a signature credential-harvesting phishing site.";
      } else if (contentRiskScore > 30) {
        aiVerdict = "SUSPICIOUS: Potential security threat. The page contains urgent action prompts or mismatched links. Avoid entering credentials or personal info.";
      } else if (contentRiskScore > 0) {
        aiVerdict = "SAFE / CAUTION: Minor content signals detected, but no clear deceptive patterns found. Always verify the domain name in the address bar.";
      }
    }

    let finalScore = 0;
    let finalReasons = [];

    if (isTrusted) {
      finalScore = 0;
      finalReasons = ['Site is explicitly trusted by the user.'];
      status = 'Safe';
    } else if (isSearchEngine) {
      finalScore = 0;
      finalReasons = ['Known Search Engine.'];
      status = 'Safe';
    } else {
      finalScore = Math.max(staticScore, contentRiskScore);
      const uniqueReasons = new Set([...reasons, ...contentReasons]);
      finalReasons = Array.from(uniqueReasons);

      if (finalScore <= 30) {
        status = 'Safe';
      } else if (finalScore <= 60) {
        status = 'Suspicious';
      } else {
        status = 'Dangerous';
      }
    }

    if (isTrusted) {
      finalReasons.push('Site is explicitly trusted by the user.');
    }

    return {
      score: finalScore,
      reasons: finalReasons,
      status,
      isTrusted,
      isSearchEngine,
      contentRiskScore,
      aiVerdict,
      detectedThreats
    };

  } catch (e) {
    return { 
      score: 0, 
      reasons: ['Invalid URL format.'], 
      status: 'Safe', 
      isTrusted: false, 
      isSearchEngine: false,
      contentRiskScore: 0,
      aiVerdict: "SAFE: No deceptive text, mismatched links, or unauthorized sensitive forms were detected on this page.",
      detectedThreats: []
    };
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

            const data = { 
              score: urlScore, 
              reasons: urlReasons, 
              status, 
              isTrusted: false, 
              isSearchEngine: false,
              contentRiskScore: 0,
              aiVerdict: "Analyzing page content...",
              detectedThreats: []
            };
            
            let isHttps = false;
            try {
              isHttps = (new URL(originalUrl).protocol === 'https:');
            } catch(e){}
            data.isHttps = isHttps;

            try {
              const hostname = new URL(originalUrl).hostname;
              const apex = getApexDomain(hostname);
              chrome.storage.local.get(['domainAgeCache'], (store) => {
                const cache = store.domainAgeCache || {};
                data.domainAge = cache[apex] ? cache[apex].age : 'age unavailable';
                sendResponse(data);
              });
            } catch(e) {
              data.domainAge = 'age unavailable';
              sendResponse(data);
            }
            return;
          }
        } catch (e) { }
      }

      let cached = tabScores.get(tabId);
      if (!cached) {
        let result = calculateRiskScore(targetUrl);
        result.contentChecksComplete = result.isSearchEngine || result.isTrusted;
        cached = result;
        tabScores.set(tabId, cached);
      }

      let isHttps = false;
      try {
        isHttps = (new URL(targetUrl).protocol === 'https:');
      } catch (e) {}
      cached.isHttps = isHttps;

      const finishResponse = (data) => {
        if (!data.domainAge || data.domainAge === 'Loading...') {
          try {
            const hostname = new URL(targetUrl).hostname;
            const apex = getApexDomain(hostname);
            if (apex) {
              chrome.storage.local.get(['domainAgeCache'], (store) => {
                const cache = store.domainAgeCache || {};
                data.domainAge = cache[apex] ? cache[apex].age : 'age unavailable';
                sendResponse(data);
              });
              return;
            }
          } catch(e) {}
          data.domainAge = 'age unavailable';
        }
        sendResponse(data);
      };

      if (cached.contentChecksComplete) {
        finishResponse(cached);
      } else {
        if (!pendingInfoRequests.has(tabId)) {
          pendingInfoRequests.set(tabId, []);
        }
        let resolved = false;
        const resolve = (data) => {
          if (!resolved) {
            resolved = true;
            finishResponse(data);
          }
        };
        pendingInfoRequests.get(tabId).push(resolve);

        setTimeout(() => {
          if (!resolved) {
            resolved = true;
            const pending = pendingInfoRequests.get(tabId);
            if (pending) {
              const idx = pending.indexOf(resolve);
              if (idx !== -1) pending.splice(idx, 1);
            }
            let current = tabScores.get(tabId) || cached;
            finishResponse(current);
          }
        }, 2000);
      }
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
    const { url } = message;
    const tabId = sender.tab ? sender.tab.id : message.tabId;

    if (extensionEnabled) {
      let finalData = calculateRiskScore(url, message);
      
      let isHttps = false;
      let hostname = 'Unknown';
      try {
        const parsedUrl = new URL(url);
        isHttps = (parsedUrl.protocol === 'https:');
        hostname = parsedUrl.hostname;
      } catch(e) {}

      finalData.isHttps = isHttps;
      finalData.contentChecksComplete = true;

      const preExisting = tabScores.get(tabId);
      if (preExisting && preExisting.domainAge && preExisting.domainAge !== 'Loading...') {
        finalData.domainAge = preExisting.domainAge;
      } else {
        finalData.domainAge = 'Loading...';
        fetchAndCacheDomainAge(hostname).then(age => {
          const s = tabScores.get(tabId);
          if (s) {
            s.domainAge = age;
          }
        });
      }

      tabScores.set(tabId, finalData);

      const pending = pendingInfoRequests.get(tabId);
      if (pending) {
        pending.forEach(resolve => resolve(finalData));
        pendingInfoRequests.delete(tabId);
      }

      if (protectionModeEnabled && !finalData.isTrusted && (finalData.status === 'Dangerous' || finalData.status === 'Suspicious')) {
        routeTab(tabId, url, finalData);
      }

      sendResponse({ 
        status: finalData.status, 
        score: finalData.score, 
        protectionModeEnabled, 
        soundAlertsEnabled, 
        isSearchEngine: finalData.isSearchEngine,
        contentRiskScore: finalData.contentRiskScore,
        aiVerdict: finalData.aiVerdict,
        detectedThreats: finalData.detectedThreats,
        isHttps: finalData.isHttps,
        domainAge: finalData.domainAge
      });
      
    } else {
      sendResponse({ status: 'Disabled', score: 0 });
    }
    return true; // async callback
  }
});

// Intercept navigation before fully loading (The early interception is back to working!)
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0 || !extensionEnabled) return; // Main frame only
  if (details.url.startsWith('chrome-extension://')) return; // ignore our own pages

  const result = calculateRiskScore(details.url);
  const isComplete = result.isSearchEngine || result.isTrusted;
  
  try {
    const hostname = new URL(details.url).hostname;
    fetchAndCacheDomainAge(hostname).then(age => {
      const s = tabScores.get(details.tabId);
      if (s) {
        s.domainAge = age;
      }
    });
  } catch(e) {}

  result.domainAge = 'Loading...';
  try {
    result.isHttps = (new URL(details.url).protocol === 'https:');
  } catch(e) {
    result.isHttps = false;
  }

  result.contentChecksComplete = isComplete;
  tabScores.set(details.tabId, result);
  pendingInfoRequests.delete(details.tabId);

  if (protectionModeEnabled && !result.isTrusted && (result.status === 'Dangerous' || result.status === 'Suspicious')) {
    routeTab(details.tabId, details.url, result);
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    if (changeInfo.url.startsWith('chrome-extension://')) return;
    const result = calculateRiskScore(changeInfo.url);
    const isComplete = result.isSearchEngine || result.isTrusted;
    
    try {
      const hostname = new URL(changeInfo.url).hostname;
      fetchAndCacheDomainAge(hostname).then(age => {
        const s = tabScores.get(tabId);
        if (s) {
          s.domainAge = age;
        }
      });
    } catch(e) {}

    result.domainAge = 'Loading...';
    try {
      result.isHttps = (new URL(changeInfo.url).protocol === 'https:');
    } catch(e) {
      result.isHttps = false;
    }

    result.contentChecksComplete = isComplete;
    tabScores.set(tabId, result);
    pendingInfoRequests.delete(tabId);

    if (protectionModeEnabled && !result.isTrusted && (result.status === 'Dangerous' || result.status === 'Suspicious')) {
      routeTab(tabId, changeInfo.url, result);
    }
  }

  if (changeInfo.status === 'complete' && tab.url && !tab.url.startsWith('chrome')) {
    if (!tabScores.has(tabId)) {
      const result = calculateRiskScore(tab.url);
      result.contentChecksComplete = result.isSearchEngine || result.isTrusted;
      tabScores.set(tabId, result);
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabScores.delete(tabId);
  pendingInfoRequests.delete(tabId);
});