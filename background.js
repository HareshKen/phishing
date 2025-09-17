// Enhanced Background service worker for phishing detection extension with API integration

// Configuration
const CONFIG = {
    API_URL: 'http://localhost:5000/analyze', // Backend API endpoint
    BATCH_API_URL: 'http://localhost:5000/batch',
    HEALTH_CHECK_URL: 'http://localhost:5000/health',
    FALLBACK_ENABLED: true,
    CACHE_DURATION: 30 * 60 * 1000, // 30 minutes
    ANALYSIS_DELAY: 1000, // 1 second delay before analysis
    MAX_RETRIES: 2
};

// Enhanced Phishing Detection Class with API Integration
class PhishingDetector {
    constructor() {
        this.features = {
            phishingKeywords: [
                'verify', 'confirm', 'update', 'secure', 'login', 'account', 
                'suspend', 'expire', 'urgent', 'immediate', 'click', 'alert',
                'banking', 'paypal', 'amazon', 'microsoft', 'apple', 'google',
                'suspended', 'limited', 'verify', 'authentication', 'security'
            ],
            
            suspiciousTlds: [
                '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.work',
                '.loan', '.cricket', '.science', '.party', '.date', '.racing',
                '.accountant', '.review', '.country', '.stream', '.trade',
                '.bid', '.webcam', '.xin', '.win'
            ],
            
            legitimateDomains: [
                'google.com', 'amazon.com', 'facebook.com', 'microsoft.com',
                'apple.com', 'github.com', 'wikipedia.org', 'youtube.com',
                'twitter.com', 'instagram.com', 'linkedin.com', 'paypal.com',
                'ebay.com', 'netflix.com', 'yahoo.com', 'reddit.com',
                'stackoverflow.com', 'medium.com'
            ],
            
            shorteners: [
                'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
                'short.link', 'is.gd', 'tiny.cc', 'adf.ly', 'shorturl.at',
                'cutt.ly', 'rebrand.ly'
            ]
        };
        
        this.cache = new Map();
        this.pendingAnalyses = new Map();
    }
    
    // API-first analysis with fallback
    async analyzeUrl(url) {
        // Check cache first
        const cacheKey = this.getCacheKey(url);
        const cached = this.cache.get(cacheKey);
        if (cached && Date.now() - cached.timestamp < CONFIG.CACHE_DURATION) {
            return cached.result;
        }
        
        // Check if analysis is already in progress
        if (this.pendingAnalyses.has(url)) {
            return this.pendingAnalyses.get(url);
        }
        
        // Start new analysis
        const analysisPromise = this.performAnalysis(url);
        this.pendingAnalyses.set(url, analysisPromise);
        
        try {
            const result = await analysisPromise;
            
            // Cache result
            this.cache.set(cacheKey, {
                result: result,
                timestamp: Date.now()
            });
            
            return result;
        } finally {
            this.pendingAnalyses.delete(url);
        }
    }
    
    async performAnalysis(url) {
        // Try API first
        try {
            const apiResult = await this.analyzeWithAPI(url);
            if (apiResult && !apiResult.error) {
                return this.normalizeAPIResult(apiResult, url);
            }
        } catch (error) {
            console.warn('API analysis failed:', error.message);
        }
        
        // Fallback to local analysis
        if (CONFIG.FALLBACK_ENABLED) {
            return this.localAnalysis(url);
        }
        
        throw new Error('Analysis failed and fallback is disabled');
    }
    
    async analyzeWithAPI(url) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
        
        try {
            const response = await fetch(CONFIG.API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url }),
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                throw new Error(`API responded with status ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            clearTimeout(timeoutId);
            throw error;
        }
    }
    
    normalizeAPIResult(apiResult, url) {
        // Convert API response to standard format
        const prediction = apiResult.prediction || 
                          (apiResult.is_phishing ? 'phishing' : 
                           apiResult.risk_level === 'HIGH' ? 'phishing' :
                           apiResult.risk_level === 'MEDIUM' ? 'warning' : 'legitimate');
        
        const confidence = apiResult.confidence || apiResult.risk_score || 0.5;
        const analysis = apiResult.analysis || ['API analysis completed'];
        
        return {
            url: url,
            prediction: prediction,
            confidence: confidence,
            phishingProbability: apiResult.phishing_probability || (prediction === 'phishing' ? 0.8 : prediction === 'warning' ? 0.5 : 0.2),
            analysis: analysis,
            features: apiResult.features || {},
            source: 'api',
            timestamp: Date.now()
        };
    }
    
    // Enhanced local analysis fallback
    localAnalysis(url) {
        const features = this.extractFeatures(url);
        let phishingScore = 0;
        let legitimateScore = 0;
        const analysis = [];
        
        // Enhanced scoring algorithm
        
        // URL length analysis
        if (features.urlLength > 100) {
            phishingScore += 15;
            analysis.push("⚠️ Very long URL (suspicious)");
        } else if (features.urlLength > 75) {
            phishingScore += 8;
            analysis.push("⚠️ Long URL");
        } else if (features.urlLength < 20) {
            phishingScore += 5;
            analysis.push("⚠️ Unusually short URL");
        }
        
        // Protocol analysis
        if (features.httpsUsed) {
            legitimateScore += 12;
            analysis.push("✅ Uses HTTPS encryption");
        } else {
            phishingScore += 25;
            analysis.push("🔓 No HTTPS - insecure connection");
        }
        
        // IP address usage
        if (features.hasIp) {
            phishingScore += 30;
            analysis.push("🚨 Uses IP address instead of domain name");
        }
        
        // Suspicious keywords
        if (features.phishingKeywords > 0) {
            const keywordScore = Math.min(features.phishingKeywords * 12, 40);
            phishingScore += keywordScore;
            analysis.push(`🔍 Contains ${features.phishingKeywords} suspicious keyword(s)`);
        }
        
        // TLD analysis
        if (features.hasSuspiciousTld) {
            phishingScore += 25;
            analysis.push("⚠️ Uses suspicious top-level domain");
        }
        
        // Legitimate domain verification
        if (features.isLegitimateService) {
            legitimateScore += 35;
            analysis.push("✅ Matches known legitimate service");
        } else {
            // Enhanced spoofing detection
            const domain = url.toLowerCase();
            for (let legitDomain of this.features.legitimateDomains) {
                const variations = [
                    legitDomain.replace(/\./g, '-'),
                    legitDomain.replace(/\./g, ''),
                    legitDomain + '-',
                    legitDomain.replace('o', '0'),
                    legitDomain.replace('e', '3'),
                    legitDomain.replace('a', '@')
                ];
                
                for (let variation of variations) {
                    if (domain.includes(variation) && domain !== legitDomain) {
                        phishingScore += 30;
                        analysis.push(`🎭 Possible spoofing attempt of ${legitDomain}`);
                        break;
                    }
                }
            }
        }
        
        // URL shortener detection
        if (features.isShortened) {
            phishingScore += 18;
            analysis.push("🔗 Uses URL shortener (destination hidden)");
        }
        
        // Subdomain analysis
        if (features.subdomainCount > 3) {
            phishingScore += 15;
            analysis.push("🌐 Excessive subdomains (highly suspicious)");
        } else if (features.subdomainCount > 1) {
            phishingScore += 8;
            analysis.push("🌐 Multiple subdomains");
        }
        
        // Domain entropy (randomness)
        if (features.domainEntropy > 4.5) {
            phishingScore += 20;
            analysis.push("🎲 Domain contains random character patterns");
        } else if (features.domainEntropy > 3.5) {
            phishingScore += 10;
            analysis.push("🎲 Domain has unusual character patterns");
        }
        
        // Path analysis
        if (features.hasSuspiciousPath) {
            phishingScore += 12;
            analysis.push("📁 Suspicious path structure detected");
        }
        
        // Parameter analysis
        if (features.hasSuspiciousParams) {
            phishingScore += 10;
            analysis.push("🔗 Suspicious URL parameters");
        }
        
        // Port analysis
        if (features.hasPort) {
            phishingScore += 15;
            analysis.push("🔌 Uses non-standard network port");
        }
        
        // Character analysis
        if (features.digitRatio > 0.4) {
            phishingScore += 12;
            analysis.push("🔢 Unusually high number count in URL");
        }
        
        if (features.specialCharCount > features.urlLength * 0.6) {
            phishingScore += 10;
            analysis.push("⚡ High special character density");
        }
        
        // Calculate prediction with improved thresholds
        const totalScore = phishingScore + legitimateScore;
        const phishingProbability = totalScore > 0 ? phishingScore / totalScore : 0;
        
        let prediction, confidence;
        if (phishingProbability > 0.7) {
            prediction = 'phishing';
            confidence = Math.min(0.95, 0.7 + (phishingProbability - 0.7) * 0.8);
        } else if (phishingProbability > 0.4) {
            prediction = 'warning';
            confidence = 0.6 + Math.abs(0.55 - phishingProbability) * 0.7;
        } else {
            prediction = 'legitimate';
            confidence = Math.min(0.95, 0.8 + (0.4 - phishingProbability) * 0.5);
        }
        
        return {
            url: url,
            prediction,
            confidence,
            phishingProbability,
            analysis: analysis.slice(0, 8),
            features,
            source: 'local_fallback',
            timestamp: Date.now()
        };
    }
    
    extractFeatures(url) {
        const features = {};
        const urlLower = url.toLowerCase();
        
        try {
            const parsedUrl = new URL(url.startsWith('http') ? url : 'http://' + url);
            const domain = parsedUrl.hostname;
            const path = parsedUrl.pathname;
            const query = parsedUrl.search;
            
            // Basic features
            features.urlLength = url.length;
            features.domainLength = domain.length;
            features.pathLength = path.length;
            features.queryLength = query.length;
            
            // Security features
            features.httpsUsed = url.startsWith('https://') ? 1 : 0;
            features.hasPort = domain.includes(':') && !domain.includes('www') ? 1 : 0;
            features.hasIp = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(domain) ? 1 : 0;
            
            // Character analysis
            features.digitCount = (url.match(/\d/g) || []).length;
            features.specialCharCount = (url.match(/[^a-zA-Z0-9]/g) || []).length;
            features.digitRatio = features.digitCount / url.length;
            
            // Keyword analysis
            features.phishingKeywords = this.features.phishingKeywords.filter(
                keyword => urlLower.includes(keyword)
            ).length;
            
            // Domain features
            features.hasSuspiciousTld = this.features.suspiciousTlds.some(
                tld => domain.endsWith(tld)
            ) ? 1 : 0;
            
            features.isLegitimateService = this.features.legitimateDomains.some(
                legitDomain => domain.includes(legitDomain)
            ) ? 1 : 0;
            
            features.isShortened = this.features.shorteners.some(
                shortener => domain.includes(shortener)
            ) ? 1 : 0;
            
            // Advanced domain analysis
            const domainParts = domain.split('.');
            features.subdomainCount = Math.max(0, domainParts.length - 2);
            features.domainEntropy = this.calculateEntropy(domain);
            
            // Path analysis
            features.pathDepth = path.split('/').filter(part => part.length > 0).length;
            features.hasSuspiciousPath = /\/(admin|login|secure|verify|confirm|update|signin|account)/.test(path) ? 1 : 0;
            
            // Query parameter analysis
            if (query) {
                const params = new URLSearchParams(query);
                features.paramCount = params.size;
                features.hasSuspiciousParams = Array.from(params.keys()).some(
                    key => ['redirect', 'url', 'link', 'goto', 'next', 'continue', 'return'].includes(key.toLowerCase())
                ) ? 1 : 0;
            } else {
                features.paramCount = 0;
                features.hasSuspiciousParams = 0;
            }
            
        } catch (error) {
            console.warn('Feature extraction error:', error);
            features.parsingError = 1;
        }
        
        return features;
    }
    
    calculateEntropy(text) {
        if (!text) return 0;
        
        const freq = {};
        for (let char of text) {
            freq[char] = (freq[char] || 0) + 1;
        }
        
        let entropy = 0;
        const length = text.length;
        for (let char in freq) {
            const p = freq[char] / length;
            entropy -= p * Math.log2(p);
        }
        
        return entropy;
    }
    
    getCacheKey(url) {
        return url.toLowerCase().trim();
    }
    
    // Clean old cache entries
    cleanCache() {
        const now = Date.now();
        for (let [key, value] of this.cache.entries()) {
            if (now - value.timestamp > CONFIG.CACHE_DURATION) {
                this.cache.delete(key);
            }
        }
    }
}

// Initialize detector
const detector = new PhishingDetector();

// Settings management
let settings = {
    realtimeProtection: true,
    notifications: true,
    autoBlock: false
};

// Load settings on startup
chrome.storage.sync.get({
    realtimeProtection: true,
    notifications: true,
    autoBlock: false
}).then((result) => {
    settings = result;
    console.log('Settings loaded:', settings);
});

// Enhanced tab update listener with debouncing
let analysisTimeouts = new Map();

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'loading' && tab.url && settings.realtimeProtection) {
        // Skip chrome:// and extension URLs
        if (tab.url.startsWith('chrome://') || 
            tab.url.startsWith('chrome-extension://') ||
            tab.url.startsWith('moz-extension://')) {
            return;
        }
        
        // Clear existing timeout for this tab
        if (analysisTimeouts.has(tabId)) {
            clearTimeout(analysisTimeouts.get(tabId));
        }
        
        // Set new timeout to avoid rapid-fire analyses
        const timeoutId = setTimeout(async () => {
            try {
                console.log('Analyzing URL:', tab.url);
                const result = await detector.analyzeUrl(tab.url);
                
                // Update badge
                await updateBadge(tabId, result);
                
                // Handle phishing detection
                await handleThreatDetection(tabId, tab.url, result);
                
                // Store result for popup
                await chrome.storage.local.set({
                    [`analysis_${tabId}`]: {
                        url: tab.url,
                        result: result,
                        timestamp: Date.now()
                    }
                });
                
                // Send to content script if available
                try {
                    await chrome.tabs.sendMessage(tabId, {
                        action: 'analysisResult',
                        result: result
                    });
                } catch (contentError) {
                    // Content script not ready or not available
                    console.log('Content script not available for tab', tabId);
                }
                
            } catch (error) {
                console.error('Error analyzing URL:', error);
                
                // Set error badge
                await chrome.action.setBadgeText({ text: '⚠', tabId: tabId });
                await chrome.action.setBadgeBackgroundColor({ color: '#ffc107', tabId: tabId });
            }
        }, CONFIG.ANALYSIS_DELAY);
        
        analysisTimeouts.set(tabId, timeoutId);
    }
});

// Enhanced threat detection handling
async function handleThreatDetection(tabId, url, result) {
    const { prediction, confidence } = result;
    
    if (prediction === 'phishing' && settings.autoBlock) {
        // Block the page
        try {
            await chrome.tabs.update(tabId, {
                url: chrome.runtime.getURL('warning.html') + '?blocked=' + encodeURIComponent(url)
            });
            console.log('Blocked phishing site:', url);
        } catch (error) {
            console.error('Error blocking site:', error);
        }
    } else if (prediction === 'phishing' && settings.notifications) {
        // Show high-priority notification
        chrome.notifications.create(`phishing_${tabId}`, {
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: '🚨 Phishing Site Detected!',
            message: `Warning: This site appears to be a phishing attempt.\nConfidence: ${(confidence * 100).toFixed(1)}%`,
            priority: 2,
            requireInteraction: true
        });
    } else if (prediction === 'warning' && settings.notifications) {
        // Show warning notification
        chrome.notifications.create(`warning_${tabId}`, {
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: '⚠️ Suspicious Site Detected',
            message: `Caution: This site has suspicious characteristics.\nConfidence: ${(confidence * 100).toFixed(1)}%`,
            priority: 1
        });
    }
}

// Enhanced badge update with better visual feedback
async function updateBadge(tabId, result) {
    let badgeText = '';
    let badgeColor = '#666666';
    let title = 'Phishing Detector';
    
    switch (result.prediction) {
        case 'phishing':
            badgeText = '🚨';
            badgeColor = '#dc3545';
            title = `PHISHING DETECTED - ${(result.confidence * 100).toFixed(1)}% confidence`;
            break;
        case 'warning':
            badgeText = '⚠️';
            badgeColor = '#ffc107';
            title = `Suspicious site - ${(result.confidence * 100).toFixed(1)}% confidence`;
            break;
        case 'legitimate':
            badgeText = '✅';
            badgeColor = '#28a745';
            title = `Safe site - ${(result.confidence * 100).toFixed(1)}% confidence`;
            break;
        default:
            badgeText = '?';
            badgeColor = '#6c757d';
            title = 'Analysis incomplete';
    }
    
    await chrome.action.setBadgeText({ text: badgeText, tabId: tabId });
    await chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId: tabId });
    await chrome.action.setTitle({ title: title, tabId: tabId });
}

// Enhanced message listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('Received message:', message.action);
    
    switch (message.action) {
        case 'analyzeUrl':
            // URL analysis request from popup
            detector.analyzeUrl(message.url)
                .then(result => {
                    console.log('Analysis result:', result);
                    sendResponse(result);
                })
                .catch(error => {
                    console.error('Analysis failed:', error);
                    sendResponse({ error: error.message });
                });
            return true; // Async response
            
        case 'settingsUpdated':
            // Settings update from popup
            settings[message.setting] = message.value;
            chrome.storage.sync.set({ [message.setting]: message.value });
            console.log(`Setting ${message.setting} updated to ${message.value}`);
            break;
            
        case 'getAnalysis':
            // Get stored analysis for current tab
            chrome.storage.local.get(`analysis_${message.tabId}`)
                .then(result => {
                    sendResponse(result[`analysis_${message.tabId}`] || null);
                })
                .catch(error => {
                    console.error('Error getting analysis:', error);
                    sendResponse(null);
                });
            return true; // Async response
            
        case 'contentScriptReady':
            // Content script is ready, send current analysis if available
            if (sender.tab) {
                chrome.storage.local.get(`analysis_${sender.tab.id}`)
                    .then(result => {
                        const analysis = result[`analysis_${sender.tab.id}`];
                        if (analysis) {
                            chrome.tabs.sendMessage(sender.tab.id, {
                                action: 'analysisResult',
                                result: analysis.result
                            }).catch(error => {
                                console.log('Could not send to content script:', error.message);
                            });
                        }
                    });
            }
            break;
            
        case 'ping':
            // Health check from popup
            sendResponse({ status: 'ok', timestamp: Date.now() });
            break;
            
        case 'clearCache':
            // Clear analysis cache
            detector.cache.clear();
            sendResponse({ status: 'cache_cleared' });
            break;
            
        case 'getStats':
            // Get extension stats
            sendResponse({
                cacheSize: detector.cache.size,
                settings: settings,
                apiUrl: CONFIG.API_URL,
                version: '1.0.0'
            });
            break;
    }
});

// Clean up old analysis data and cache periodically
setInterval(async () => {
    try {
        // Clean analysis cache
        detector.cleanCache();
        
        // Clean old stored analyses
        const items = await chrome.storage.local.get();
        const oneHourAgo = Date.now() - (60 * 60 * 1000);
        
        const keysToRemove = [];
        for (const key in items) {
            if (key.startsWith('analysis_') && 
                items[key].timestamp && 
                items[key].timestamp < oneHourAgo) {
                keysToRemove.push(key);
            }
        }
        
        if (keysToRemove.length > 0) {
            await chrome.storage.local.remove(keysToRemove);
            console.log(`Cleaned ${keysToRemove.length} old analysis records`);
        }
        
        // Clean analysis timeouts
        for (let [tabId, timeoutId] of analysisTimeouts.entries()) {
            try {
                const tab = await chrome.tabs.get(tabId);
                if (!tab) {
                    clearTimeout(timeoutId);
                    analysisTimeouts.delete(tabId);
                }
            } catch (error) {
                // Tab doesn't exist anymore
                clearTimeout(timeoutId);
                analysisTimeouts.delete(tabId);
            }
        }
        
    } catch (error) {
        console.error('Error during cleanup:', error);
    }
}, 10 * 60 * 1000); // Clean every 10 minutes

// Handle tab removal
chrome.tabs.onRemoved.addListener((tabId) => {
    // Clear analysis timeout
    if (analysisTimeouts.has(tabId)) {
        clearTimeout(analysisTimeouts.get(tabId));
        analysisTimeouts.delete(tabId);
    }
    
    // Remove stored analysis
    chrome.storage.local.remove(`analysis_${tabId}`).catch(error => {
        console.log('Could not remove analysis for closed tab:', error.message);
    });
});

// Enhanced installation handler
chrome.runtime.onInstalled.addListener((details) => {
    console.log('Extension installed/updated:', details.reason);
    
    if (details.reason === 'install') {
        // Set default settings
        chrome.storage.sync.set({
            realtimeProtection: true,
            notifications: true,
            autoBlock: false
        });
        
        // Show welcome notification
        chrome.notifications.create('welcome', {
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: '🛡️ Phishing Detector Installed!',
            message: 'Your browser is now protected against phishing attacks. Click the extension icon to configure settings.'
        });
        
        // Open welcome page (optional)
        // chrome.tabs.create({ url: chrome.runtime.getURL('welcome.html') });
        
    } else if (details.reason === 'update') {
        console.log(`Updated from version ${details.previousVersion} to ${chrome.runtime.getManifest().version}`);
        
        // Show update notification
        chrome.notifications.create('updated', {
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: '🔄 Phishing Detector Updated!',
            message: 'Extension has been updated with improved detection capabilities.'
        });
    }
});

// API health check on startup
async function checkAPIHealth() {
    try {
        const response = await fetch(CONFIG.HEALTH_CHECK_URL, {
            method: 'GET',
            signal: AbortSignal.timeout(5000)
        });
        
        if (response.ok) {
            const health = await response.json();
            console.log('API health check:', health);
            return health;
        }
    } catch (error) {
        console.warn('API health check failed:', error.message);
    }
    return null;
}

// Initialize API health check
checkAPIHealth().then(health => {
    if (health) {
        console.log('✅ API backend is available');
    } else {
        console.log('⚠️ API backend not available, using fallback mode');
    }
});

// Handle notification clicks
chrome.notifications.onClicked.addListener((notificationId) => {
    if (notificationId.startsWith('phishing_') || notificationId.startsWith('warning_')) {
        // Focus the tab that triggered the notification
        const tabId = parseInt(notificationId.split('_')[1]);
        chrome.tabs.update(tabId, { active: true }).catch(error => {
            console.log('Could not focus tab:', error.message);
        });
    }
    
    // Clear the notification
    chrome.notifications.clear(notificationId);
});

// Handle context menu (optional future feature)
chrome.runtime.onStartup.addListener(() => {
    console.log('🛡️ Phishing Detector started');
});

// Export for testing (if needed)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { PhishingDetector, detector };
}