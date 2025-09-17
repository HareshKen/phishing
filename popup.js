// Enhanced Phishing Detection Class matching the HTML version
class PhishingDetector {
    constructor() {
        this.features = {
            phishingKeywords: [
                'verify', 'confirm', 'update', 'secure', 'login', 'account', 
                'suspend', 'expire', 'urgent', 'immediate', 'click', 'alert',
                'banking', 'paypal', 'amazon', 'microsoft', 'apple', 'google'
            ],
            
            suspiciousTlds: [
                '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.work',
                '.loan', '.cricket', '.science', '.party', '.date', '.racing',
                '.accountant', '.review', '.country', '.stream', '.trade'
            ],
            
            legitimateDomains: [
                'google.com', 'amazon.com', 'facebook.com', 'microsoft.com',
                'apple.com', 'github.com', 'wikipedia.org', 'youtube.com',
                'twitter.com', 'instagram.com', 'linkedin.com', 'paypal.com',
                'ebay.com', 'netflix.com', 'yahoo.com', 'reddit.com'
            ],
            
            shorteners: [
                'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
                'short.link', 'is.gd', 'tiny.cc', 'adf.ly', 'shorturl.at'
            ]
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
            
            // Basic URL features
            features.urlLength = url.length;
            features.domainLength = domain.length;
            features.pathLength = path.length;
            features.queryLength = query.length;
            
            // Security indicators
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
            
            // Domain analysis
            features.hasSuspiciousTld = this.features.suspiciousTlds.some(
                tld => domain.endsWith(tld)
            ) ? 1 : 0;
            
            features.isLegitimateService = this.features.legitimateDomains.some(
                legitDomain => domain.includes(legitDomain)
            ) ? 1 : 0;
            
            features.isShortened = this.features.shorteners.some(
                shortener => domain.includes(shortener)
            ) ? 1 : 0;
            
            // Advanced domain features
            const domainParts = domain.split('.');
            features.subdomainCount = Math.max(0, domainParts.length - 2);
            features.domainEntropy = this.calculateEntropy(domain);
            
            // Path analysis
            features.pathDepth = path.split('/').filter(part => part.length > 0).length;
            features.hasSuspiciousPath = /\/(admin|login|secure|verify|confirm|update)/.test(path) ? 1 : 0;
            
            // Query parameter analysis
            if (query) {
                const params = new URLSearchParams(query);
                features.paramCount = params.size;
                features.hasSuspiciousParams = Array.from(params.keys()).some(
                    key => ['redirect', 'url', 'link', 'goto', 'next'].includes(key.toLowerCase())
                ) ? 1 : 0;
            } else {
                features.paramCount = 0;
                features.hasSuspiciousParams = 0;
            }
            
        } catch (error) {
            features.parsingError = 1;
            console.warn('URL parsing error:', error);
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
    
    predict(url) {
        const features = this.extractFeatures(url);
        let phishingScore = 0;
        let legitimateScore = 0;
        const analysis = [];
        
        // Enhanced scoring with more sophisticated analysis
        
        // URL length analysis
        if (features.urlLength > 100) {
            phishingScore += 15;
            analysis.push("⚠️ Very long URL (suspicious)");
        } else if (features.urlLength > 50) {
            phishingScore += 5;
            analysis.push("⚠️ Long URL");
        }
        
        // Security protocol check
        if (features.httpsUsed) {
            legitimateScore += 10;
            analysis.push("✅ Uses HTTPS");
        } else {
            phishingScore += 20;
            analysis.push("🔓 No HTTPS (insecure)");
        }
        
        // IP address usage
        if (features.hasIp) {
            phishingScore += 25;
            analysis.push("🚨 Uses IP address instead of domain");
        }
        
        // Suspicious keywords
        if (features.phishingKeywords > 0) {
            phishingScore += features.phishingKeywords * 10;
            analysis.push(`🔍 Contains ${features.phishingKeywords} suspicious keyword(s)`);
        }
        
        // TLD analysis
        if (features.hasSuspiciousTld) {
            phishingScore += 20;
            analysis.push("⚠️ Uses suspicious top-level domain");
        }
        
        // Legitimate service verification
        if (features.isLegitimateService) {
            legitimateScore += 30;
            analysis.push("✅ Matches known legitimate service");
        } else {
            // Check for domain spoofing
            const domain = url.toLowerCase();
            for (let legitDomain of this.features.legitimateDomains) {
                if (domain.includes(legitDomain) && 
                    !domain.includes(`www.${legitDomain}`) && 
                    !domain.includes(`${legitDomain}/`) &&
                    domain !== legitDomain) {
                    phishingScore += 25;
                    analysis.push(`🎭 Possible spoofing of ${legitDomain}`);
                    break;
                }
            }
        }
        
        // URL shortener check
        if (features.isShortened) {
            phishingScore += 15;
            analysis.push("🔗 Uses URL shortener (hides destination)");
        }
        
        // Subdomain analysis
        if (features.subdomainCount > 2) {
            phishingScore += 10;
            analysis.push("🌐 Many subdomains (suspicious)");
        }
        
        // Domain entropy (randomness)
        if (features.domainEntropy > 4) {
            phishingScore += 15;
            analysis.push("🎲 Domain has high randomness");
        }
        
        // Suspicious path detection
        if (features.hasSuspiciousPath) {
            phishingScore += 10;
            analysis.push("📁 Suspicious path detected");
        }
        
        // Parameter analysis
        if (features.hasSuspiciousParams) {
            phishingScore += 8;
            analysis.push("🔗 Suspicious URL parameters");
        }
        
        // Port usage (non-standard)
        if (features.hasPort) {
            phishingScore += 12;
            analysis.push("🔌 Uses non-standard port");
        }
        
        // Character distribution analysis
        if (features.digitRatio > 0.3) {
            phishingScore += 8;
            analysis.push("🔢 High digit ratio in URL");
        }
        
        // Calculate final prediction with improved algorithm
        const totalScore = phishingScore + legitimateScore;
        const phishingProbability = totalScore > 0 ? phishingScore / totalScore : 0;
        
        let prediction, confidence;
        if (phishingProbability > 0.65) {
            prediction = 'phishing';
            confidence = Math.min(0.95, 0.65 + (phishingProbability - 0.65) * 0.6);
        } else if (phishingProbability > 0.35) {
            prediction = 'warning';
            confidence = 0.6 + Math.abs(0.5 - phishingProbability) * 0.8;
        } else {
            prediction = 'legitimate';
            confidence = Math.min(0.95, 0.75 + (0.35 - phishingProbability) * 0.6);
        }
        
        return {
            prediction,
            confidence,
            phishingProbability,
            analysis: analysis.slice(0, 8), // Limit analysis items
            features
        };
    }
}

// Initialize detector
const detector = new PhishingDetector();

// DOM elements
const currentUrlElement = document.getElementById('currentUrl');
const currentStatusElement = document.getElementById('currentStatus');
const manualUrlInput = document.getElementById('manualUrl');
const analyzeBtn = document.getElementById('analyzeBtn');
const analysisResult = document.getElementById('analysisResult');
const realtimeToggle = document.getElementById('realtimeToggle');
const notificationsToggle = document.getElementById('notificationsToggle');
const autoBlockToggle = document.getElementById('autoBlockToggle');

// Initialize popup with enhanced functionality
document.addEventListener('DOMContentLoaded', async () => {
    console.log('Phishing Detector popup loaded');
    await loadSettings();
    await analyzeCurrentTab();
    setupEventListeners();
});

// Load settings from storage with enhanced defaults
async function loadSettings() {
    try {
        const result = await chrome.storage.sync.get({
            realtimeProtection: true,
            notifications: true,
            autoBlock: false
        });
        
        updateToggle(realtimeToggle, result.realtimeProtection);
        updateToggle(notificationsToggle, result.notifications);
        updateToggle(autoBlockToggle, result.autoBlock);
        
        console.log('Settings loaded:', result);
    } catch (error) {
        console.error('Error loading settings:', error);
    }
}

// Update toggle appearance with smooth animation
function updateToggle(toggle, isActive) {
    if (isActive) {
        toggle.classList.add('active');
    } else {
        toggle.classList.remove('active');
    }
}

// Setup event listeners with enhanced functionality
function setupEventListeners() {
    // Manual URL analysis
    analyzeBtn.addEventListener('click', analyzeManualUrl);
    manualUrlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            analyzeManualUrl();
        }
    });
    
    // Enhanced input validation
    manualUrlInput.addEventListener('input', (e) => {
        const value = e.target.value.trim();
        if (value && !value.startsWith('http')) {
            // Auto-suggest protocol
            if (value.includes('.')) {
                e.target.style.borderColor = 'rgba(255, 193, 7, 0.5)';
            }
        } else {
            e.target.style.borderColor = 'rgba(255, 255, 255, 0.2)';
        }
    });
    
    // Settings toggles with enhanced feedback
    realtimeToggle.addEventListener('click', () => toggleSetting('realtimeProtection', realtimeToggle));
    notificationsToggle.addEventListener('click', () => toggleSetting('notifications', notificationsToggle));
    autoBlockToggle.addEventListener('click', () => toggleSetting('autoBlock', autoBlockToggle));
}

// Enhanced toggle setting with feedback
async function toggleSetting(setting, toggle) {
    const isActive = toggle.classList.contains('active');
    const newValue = !isActive;
    
    // Visual feedback
    toggle.style.transform = 'scale(0.95)';
    setTimeout(() => {
        toggle.style.transform = 'scale(1)';
    }, 150);
    
    updateToggle(toggle, newValue);
    
    try {
        await chrome.storage.sync.set({ [setting]: newValue });
        
        // Notify background script
        chrome.runtime.sendMessage({
            action: 'settingsUpdated',
            setting: setting,
            value: newValue
        });
        
        // Show brief feedback
        showNotification(`${setting.replace(/([A-Z])/g, ' $1').toLowerCase()} ${newValue ? 'enabled' : 'disabled'}`, 'success');
        
    } catch (error) {
        console.error('Error updating setting:', error);
        // Revert toggle on error
        updateToggle(toggle, !newValue);
        showNotification('Failed to update setting', 'error');
    }
}

// Enhanced current tab analysis
async function analyzeCurrentTab() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        if (tab && tab.url && !tab.url.startsWith('chrome://') && !tab.url.startsWith('chrome-extension://')) {
            // Display URL with truncation for long URLs
            const displayUrl = tab.url.length > 60 ? 
                tab.url.substring(0, 57) + '...' : tab.url;
            currentUrlElement.textContent = displayUrl;
            currentUrlElement.title = tab.url; // Full URL in tooltip
            
            // Show analyzing state
            currentStatusElement.innerHTML = `
                <div class="spinner"></div>
                <span>Analyzing with AI...</span>
            `;
            currentStatusElement.className = 'status analyzing';
            
            // Add small delay for better UX
            await new Promise(resolve => setTimeout(resolve, 800));
            
            // Analyze URL with enhanced detection
            const result = detector.predict(tab.url);
            displayCurrentSiteStatus(result);
            
            // Try to get cached analysis from background script
            try {
                chrome.runtime.sendMessage({
                    action: 'getAnalysis',
                    tabId: tab.id
                }, (response) => {
                    if (response && response.result) {
                        // Use background analysis if available and more recent
                        displayCurrentSiteStatus(response.result);
                    }
                });
            } catch (bgError) {
                console.warn('Background script communication failed:', bgError);
            }
            
        } else {
            currentUrlElement.textContent = 'Chrome internal page';
            currentStatusElement.innerHTML = '<span>ℹ️ Cannot analyze internal pages</span>';
            currentStatusElement.className = 'status';
        }
    } catch (error) {
        console.error('Error analyzing current tab:', error);
        currentUrlElement.textContent = 'Error loading URL';
        currentStatusElement.innerHTML = '<span>❌ Analysis failed</span>';
        currentStatusElement.className = 'status';
    }
}

// Enhanced current site status display
function displayCurrentSiteStatus(result) {
    const { prediction, confidence, analysis } = result;
    
    let icon, text, className, additionalInfo = '';
    
    switch (prediction) {
        case 'legitimate':
            icon = '✅';
            text = 'Safe Site';
            className = 'status safe';
            additionalInfo = 'This site appears legitimate';
            break;
        case 'phishing':
            icon = '🚨';
            text = 'Phishing Detected!';
            className = 'status phishing';
            additionalInfo = 'High risk - avoid this site';
            break;
        case 'warning':
            icon = '⚠️';
            text = 'Suspicious Site';
            className = 'status warning';
            additionalInfo = 'Exercise caution';
            break;
    }
    
    currentStatusElement.innerHTML = `
        <span style="font-size: 1.2em;">${icon}</span>
        <div>
            <div style="font-weight: 700;">${text}</div>
            <div style="font-size: 0.75em; opacity: 0.8; margin-top: 2px;">
                ${additionalInfo} • ${(confidence * 100).toFixed(1)}% confidence
            </div>
        </div>
    `;
    currentStatusElement.className = className;
    
    // Add pulse animation for phishing detection
    if (prediction === 'phishing') {
        currentStatusElement.style.animation = 'pulse 2s ease-in-out infinite';
    }
}

// Enhanced manual URL analysis
async function analyzeManualUrl() {
    let url = manualUrlInput.value.trim();
    
    if (!url) {
        showNotification('Please enter a URL to analyze', 'warning');
        manualUrlInput.focus();
        return;
    }
    
    // Auto-add protocol if missing
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
        manualUrlInput.value = url;
    }
    
    // Validate URL format
    try {
        new URL(url);
    } catch (error) {
        showNotification('Please enter a valid URL', 'error');
        manualUrlInput.focus();
        manualUrlInput.style.borderColor = 'rgba(220, 53, 69, 0.5)';
        setTimeout(() => {
            manualUrlInput.style.borderColor = 'rgba(255, 255, 255, 0.2)';
        }, 2000);
        return;
    }
    
    // UI feedback
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = '<div class="spinner" style="width: 16px; height: 16px; margin-right: 8px;"></div>Analyzing...';
    analysisResult.classList.add('hidden');
    
    // Add realistic processing delay
    await new Promise(resolve => setTimeout(resolve, 1200));
    
    try {
        const result = detector.predict(url);
        displayAnalysisResult(result);
        
        // Store analysis for potential background use
        try {
            chrome.runtime.sendMessage({
                action: 'analyzeUrl',
                url: url,
                result: result
            });
        } catch (bgError) {
            console.warn('Background communication failed:', bgError);
        }
        
    } catch (error) {
        console.error('Analysis error:', error);
        showNotification('Error analyzing URL: ' + error.message, 'error');
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.innerHTML = '🔬 Analyze URL';
    }
}

// Enhanced analysis result display
function displayAnalysisResult(result) {
    const { prediction, confidence, analysis, features } = result;
    
    let icon, title, description, className;
    
    switch (prediction) {
        case 'legitimate':
            icon = '✅';
            title = 'Safe URL';
            description = 'This URL appears to be legitimate and safe to visit. No suspicious patterns detected.';
            className = 'analysis-result legitimate';
            break;
        case 'phishing':
            icon = '🚨';
            title = 'Phishing Detected';
            description = 'This URL shows strong indicators of being a phishing site. <strong>Avoid visiting this link</strong> and do not enter personal information.';
            className = 'analysis-result phishing';
            break;
        case 'warning':
            icon = '⚠️';
            title = 'Suspicious URL';
            description = 'This URL has suspicious characteristics. Exercise caution before visiting and avoid entering sensitive information.';
            className = 'analysis-result warning';
            break;
    }
    
    // Create enhanced results with more detailed analysis
    const analysisItems = analysis.slice(0, 6).map(item => 
        `<div class="feature-item">${item}</div>`
    ).join('');
    
    // Additional technical details
    const technicalDetails = [];
    if (features) {
        if (features.urlLength > 80) technicalDetails.push(`📏 URL Length: ${features.urlLength} chars`);
        if (features.subdomainCount > 0) technicalDetails.push(`🌐 Subdomains: ${features.subdomainCount}`);
        if (features.domainEntropy > 3) technicalDetails.push(`🎲 Domain Entropy: ${features.domainEntropy.toFixed(2)}`);
    }
    
    analysisResult.innerHTML = `
        <div class="result-icon">${icon}</div>
        <div class="result-title">${title}</div>
        <div class="result-description">${description}</div>
        <div class="confidence">🎯 Detection Confidence: ${(confidence * 100).toFixed(1)}%</div>
        <div class="features">
            <h4>🔬 Detailed Analysis</h4>
            ${analysisItems}
            ${technicalDetails.length > 0 ? technicalDetails.map(detail => 
                `<div class="feature-item" style="opacity: 0.7;">${detail}</div>`
            ).join('') : ''}
        </div>
    `;
    
    analysisResult.className = className;
    analysisResult.classList.remove('hidden');
    
    // Scroll to results if needed
    setTimeout(() => {
        analysisResult.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 100);
}

// Enhanced notification system
function showNotification(message, type = 'info') {
    // Remove existing notifications
    const existing = document.querySelector('.notification');
    if (existing) existing.remove();
    
    // Create enhanced notification
    const notification = document.createElement('div');
    notification.className = 'notification';
    
    const colors = {
        success: '#28a745',
        error: '#dc3545',
        warning: '#ffc107',
        info: '#17a2b8'
    };
    
    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };
    
    notification.style.cssText = `
        position: fixed;
        top: 15px;
        right: 15px;
        left: 15px;
        background: ${colors[type] || colors.info};
        color: white;
        padding: 12px 16px;
        border-radius: 8px;
        font-size: 0.85em;
        font-weight: 600;
        z-index: 10000;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        backdrop-filter: blur(10px);
        animation: slideDown 0.3s ease-out;
        display: flex;
        align-items: center;
        gap: 8px;
    `;
    
    notification.innerHTML = `
        <span>${icons[type] || icons.info}</span>
        <span>${message}</span>
    `;
    
    // Add slide down animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideDown {
            from { transform: translateY(-100%); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
    `;
    document.head.appendChild(style);
    
    document.body.appendChild(notification);
    
    // Auto-remove notification
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.opacity = '0';
            notification.style.transform = 'translateY(-100%)';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
                if (style.parentNode) {
                    style.remove();
                }
            }, 300);
        }
    }, 3000);
    
    // Click to dismiss
    notification.addEventListener('click', () => {
        if (notification.parentNode) {
            notification.style.opacity = '0';
            setTimeout(() => notification.remove(), 200);
        }
    });
}

// Add keyboard shortcuts for better accessibility
document.addEventListener('keydown', (event) => {
    // Ctrl/Cmd + Enter to analyze
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
        if (document.activeElement === manualUrlInput) {
            event.preventDefault();
            analyzeManualUrl();
        }
    }
    
    // Escape to clear analysis results
    if (event.key === 'Escape') {
        if (!analysisResult.classList.contains('hidden')) {
            analysisResult.classList.add('hidden');
            manualUrlInput.focus();
        }
    }
});

// Add focus management for better UX
manualUrlInput.addEventListener('focus', () => {
    manualUrlInput.select(); // Select all text on focus
});

// Initialize enhanced error handling
window.addEventListener('error', (event) => {
    console.error('Extension error:', event.error);
    showNotification('An unexpected error occurred', 'error');
});

// Add extension health check
try {
    chrome.runtime.sendMessage({ action: 'ping' }, (response) => {
        if (!response) {
            console.warn('Background script not responding');
        }
    });
} catch (error) {
    console.warn('Extension communication issue:', error);
}