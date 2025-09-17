// Enhanced Content script for phishing detection extension

// Wait for DOM to be ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeContentScript);
} else {
    initializeContentScript();
}

function initializeContentScript() {
    // Only run on http/https pages
    if (!window.location.protocol.startsWith('http')) {
        return;
    }
    
    // Notify background script that content script is ready
    chrome.runtime.sendMessage({ action: 'contentScriptReady' }).catch(error => {
        console.log('Could not notify background script:', error.message);
    });
    
    // Initialize form monitoring
    initializeFormMonitoring();
    
    // Add security indicator
    addSecurityIndicator();
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.action) {
        case 'analysisResult':
            handleAnalysisResult(message.result);
            break;
            
        case 'showWarning':
            showPhishingWarning(message.url, message.result);
            break;
            
        case 'updateIndicator':
            updateSecurityIndicator(message.result);
            break;
    }
});

// Handle analysis result from background script
function handleAnalysisResult(result) {
    console.log('Content script received analysis:', result.prediction);
    
    if (result.prediction === 'phishing') {
        // Inject comprehensive warning for phishing sites
        injectPhishingWarning(result);
        
        // Add protective overlay
        addPhishingOverlay(result);
        
        // Highlight form fields as dangerous
        highlightFormFields('phishing');
        
    } else if (result.prediction === 'warning') {
        // Show smaller warning for suspicious sites
        injectCautionBanner(result);
        
        // Highlight form fields as suspicious
        highlightFormFields('warning');
    } else {
        // Safe site - show brief confirmation
        showSafeConfirmation(result);
    }
    
    // Update security indicator
    updateSecurityIndicator(result);
}

// Inject comprehensive phishing warning banner
function injectPhishingWarning(result) {
    // Remove existing banners
    removeExistingBanners();
    
    const banner = document.createElement('div');
    banner.id = 'phishing-detector-banner';
    banner.innerHTML = `
        <div style="
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            background: linear-gradient(135deg, #dc3545, #c82333);
            color: white;
            padding: 18px 25px;
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            font-size: 16px;
            font-weight: 600;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
            z-index: 2147483647;
            animation: slideDownBounce 0.6s ease-out;
            border-bottom: 4px solid rgba(255, 255, 255, 0.3);
        ">
            <div style="max-width: 1200px; margin: 0 auto; display: flex; align-items: center; justify-content: center; gap: 20px; flex-wrap: wrap;">
                <div style="display: flex; align-items: center; gap: 15px;">
                    <span style="font-size: 28px; animation: pulse 1.5s ease-in-out infinite;">🚨</span>
                    <div style="text-align: left;">
                        <div style="font-size: 20px; margin-bottom: 5px; font-weight: 700;">PHISHING SITE DETECTED!</div>
                        <div style="font-size: 14px; opacity: 0.9;">
                            This website is attempting to steal your personal information. 
                            <strong>Do not enter passwords or personal data.</strong>
                        </div>
                        <div style="font-size: 12px; opacity: 0.8; margin-top: 3px;">
                            Detection Confidence: ${(result.confidence * 100).toFixed(1)}% • 
                            Protected by Advanced Phishing Detector
                        </div>
                    </div>
                </div>
                <div style="display: flex; gap: 12px; flex-wrap: wrap;">
                    <button onclick="window.history.back()" style="
                        background: rgba(255, 255, 255, 0.9);
                        color: #dc3545;
                        border: none;
                        padding: 10px 18px;
                        border-radius: 8px;
                        cursor: pointer;
                        font-weight: 600;
                        font-size: 14px;
                        transition: all 0.3s ease;
                        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
                    " onmouseover="this.style.background='white'; this.style.transform='translateY(-1px)'" 
                       onmouseout="this.style.background='rgba(255, 255, 255, 0.9)'; this.style.transform='translateY(0)'">
                        ← Go Back Safely
                    </button>
                    <button onclick="this.parentElement.parentElement.parentElement.remove(); document.body.style.marginTop='0';" style="
                        background: rgba(255, 255, 255, 0.2);
                        color: white;
                        border: 2px solid rgba(255, 255, 255, 0.3);
                        padding: 8px 16px;
                        border-radius: 8px;
                        cursor: pointer;
                        font-weight: 600;
                        font-size: 14px;
                        transition: all 0.3s ease;
                    " onmouseover="this.style.background='rgba(255, 255, 255, 0.3)'" 
                       onmouseout="this.style.background='rgba(255, 255, 255, 0.2)'">
                        Dismiss Warning
                    </button>
                </div>
            </div>
        </div>
        <style>
            @keyframes slideDownBounce {
                0% { transform: translateY(-100%); opacity: 0; }
                60% { transform: translateY(10px); opacity: 0.9; }
                100% { transform: translateY(0); opacity: 1; }
            }
            @keyframes pulse {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.1); }
            }
        </style>
    `;
    
    document.body.insertBefore(banner, document.body.firstChild);
    
    // Adjust page content
    if (document.body) {
        document.body.style.marginTop = '100px';
        document.body.style.transition = 'margin-top 0.6s ease';
    }
}

// Inject caution banner for suspicious sites
function injectCautionBanner(result) {
    // Remove existing banners
    removeExistingBanners();
    
    const banner = document.createElement('div');
    banner.id = 'phishing-detector-caution';
    banner.innerHTML = `
        <div style="
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            background: linear-gradient(135deg, #ffc107, #e0a800);
            color: #212529;
            padding: 15px 25px;
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            font-size: 15px;
            font-weight: 600;
            text-align: center;
            box-shadow: 0 3px 12px rgba(0, 0, 0, 0.2);
            z-index: 2147483646;
            animation: slideDown 0.5s ease-out;
            border-bottom: 3px solid rgba(0, 0, 0, 0.1);
        ">
            <div style="max-width: 1200px; margin: 0 auto; display: flex; align-items: center; justify-content: center; gap: 15px; flex-wrap: wrap;">
                <span style="font-size: 20px;">⚠️</span>
                <div style="flex: 1; text-align: left; min-width: 200px;">
                    <div style="font-weight: 700; margin-bottom: 3px;">Suspicious Website Detected</div>
                    <div style="font-size: 13px; opacity: 0.8;">
                        Exercise caution when entering personal information • 
                        Confidence: ${(result.confidence * 100).toFixed(1)}%
                    </div>
                </div>
                <button onclick="this.parentElement.parentElement.remove(); document.body.style.marginTop='0';" style="
                    background: rgba(0, 0, 0, 0.1);
                    border: 1px solid rgba(0, 0, 0, 0.2);
                    color: #212529;
                    padding: 8px 14px;
                    border-radius: 6px;
                    cursor: pointer;
                    font-weight: 600;
                    font-size: 13px;
                    transition: all 0.3s ease;
                " onmouseover="this.style.background='rgba(0, 0, 0, 0.15)'" 
                   onmouseout="this.style.background='rgba(0, 0, 0, 0.1)'">
                    Dismiss
                </button>
            </div>
        </div>
        <style>
            @keyframes slideDown {
                from { transform: translateY(-100%); opacity: 0; }
                to { transform: translateY(0); opacity: 1; }
            }
        </style>
    `;
    
    document.body.insertBefore(banner, document.body.firstChild);
    
    // Adjust page content
    if (document.body) {
        document.body.style.marginTop = '70px';
        document.body.style.transition = 'margin-top 0.5s ease';
    }
}

// Show brief safe site confirmation
function showSafeConfirmation(result) {
    // Don't show for every safe site, only when confidence is very high
    if (result.confidence < 0.85) return;
    
    const notification = document.createElement('div');
    notification.innerHTML = `
        <div style="
            position: fixed;
            top: 20px;
            right: 20px;
            background: rgba(40, 167, 69, 0.95);
            color: white;
            padding: 12px 18px;
            border-radius: 8px;
            font-family: 'Segoe UI', sans-serif;
            font-size: 14px;
            font-weight: 600;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
            z-index: 2147483645;
            animation: slideInRight 0.4s ease-out, fadeOut 0.4s ease-out 2.6s;
            display: flex;
            align-items: center;
            gap: 8px;
        ">
            <span style="font-size: 16px;">✅</span>
            <span>Safe Site Verified</span>
        </div>
        <style>
            @keyframes slideInRight {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes fadeOut {
                from { opacity: 1; }
                to { opacity: 0; transform: translateX(100%); }
            }
        </style>
    `;
    
    document.body.appendChild(notification);
    
    // Remove after animation
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 3000);
}

// Add comprehensive phishing overlay
function addPhishingOverlay(result) {
    // Check if user has previously dismissed overlay for this domain
    const dismissKey = 'phishing-overlay-dismissed-' + window.location.hostname;
    if (localStorage.getItem(dismissKey)) {
        return;
    }
    
    const overlay = document.createElement('div');
    overlay.id = 'phishing-detector-overlay';
    overlay.innerHTML = `
        <div style="
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(220, 53, 69, 0.96);
            backdrop-filter: blur(15px);
            z-index: 2147483647;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            animation: overlayFadeIn 0.6s ease-out;
        ">
            <div style="
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(25px);
                border: 2px solid rgba(255, 255, 255, 0.2);
                border-radius: 24px;
                padding: 50px;
                max-width: 650px;
                width: 90%;
                text-align: center;
                color: white;
                box-shadow: 0 25px 50px rgba(0, 0, 0, 0.3);
                animation: overlaySlideUp 0.6s ease-out;
            ">
                <div style="font-size: 5em; margin-bottom: 25px; animation: overlayPulse 2s ease-in-out infinite;">🚨</div>
                <h2 style="font-size: 2.8em; font-weight: 700; margin-bottom: 20px; text-shadow: 0 2px 15px rgba(0, 0, 0, 0.3);">
                    DANGER: PHISHING ATTACK!
                </h2>
                <p style="font-size: 1.3em; margin-bottom: 25px; opacity: 0.95; line-height: 1.6;">
                    This website is <strong>attempting to steal your personal information</strong>. 
                    Do not enter passwords, credit card numbers, or any sensitive data.
                </p>
                <div style="
                    background: rgba(255, 255, 255, 0.15);
                    padding: 20px;
                    border-radius: 12px;
                    margin-bottom: 30px;
                    font-size: 1em;
                    border: 1px solid rgba(255, 255, 255, 0.2);
                ">
                    <div style="margin-bottom: 10px;"><strong>🎯 Detection Confidence:</strong> ${(result.confidence * 100).toFixed(1)}%</div>
                    <div style="margin-bottom: 10px;"><strong>🔍 Risk Factors Found:</strong> ${result.analysis ? result.analysis.length : 'Multiple'}</div>
                    <div style="font-size: 0.9em; opacity: 0.8;">Protected by Advanced AI Detection System</div>
                </div>
                <div style="display: flex; gap: 20px; justify-content: center; flex-wrap: wrap;">
                    <button onclick="window.history.back()" style="
                        background: rgba(255, 255, 255, 0.95);
                        color: #dc3545;
                        border: none;
                        padding: 15px 30px;
                        border-radius: 10px;
                        font-size: 1.2em;
                        font-weight: 700;
                        cursor: pointer;
                        transition: all 0.3s ease;
                        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
                    " onmouseover="this.style.background='white'; this.style.transform='translateY(-2px)'" 
                       onmouseout="this.style.background='rgba(255, 255, 255, 0.95)'; this.style.transform='translateY(0)'">
                        🛡️ Go Back to Safety
                    </button>
                    <button onclick="
                        localStorage.setItem('${dismissKey}', 'true');
                        this.parentElement.parentElement.parentElement.remove();
                    " style="
                        background: rgba(255, 255, 255, 0.2);
                        color: white;
                        border: 2px solid rgba(255, 255, 255, 0.4);
                        padding: 15px 30px;
                        border-radius: 10px;
                        font-size: 1.2em;
                        font-weight: 700;
                        cursor: pointer;
                        transition: all 0.3s ease;
                    " onmouseover="this.style.background='rgba(255, 255, 255, 0.25)'" 
                       onmouseout="this.style.background='rgba(255, 255, 255, 0.2)'">
                        ⚠️ Proceed Anyway (Dangerous)
                    </button>
                </div>
                <p style="font-size: 0.85em; margin-top: 25px; opacity: 0.7; line-height: 1.4;">
                    This warning helps protect you from identity theft, financial fraud, and data breaches.<br>
                    Your safety is our priority.
                </p>
            </div>
        </div>
        <style>
            @keyframes overlayFadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
            @keyframes overlaySlideUp {
                from { opacity: 0; transform: translateY(50px) scale(0.9); }
                to { opacity: 1; transform: translateY(0) scale(1); }
            }
            @keyframes overlayPulse {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.1); }
            }
        </style>
    `;
    
    document.body.appendChild(overlay);
}

// Highlight form fields based on threat level
function highlightFormFields(threatLevel) {
    const sensitiveInputs = document.querySelectorAll(
        'input[type="password"], input[type="email"], input[type="text"], ' +
        'input[type="tel"], input[type="number"], input[name*="card"], ' +
        'input[name*="ssn"], input[name*="social"], textarea'
    );
    
    const colors = {
        phishing: { border: '#dc3545', shadow: 'rgba(220, 53, 69, 0.5)', bg: 'rgba(220, 53, 69, 0.05)' },
        warning: { border: '#ffc107', shadow: 'rgba(255, 193, 7, 0.4)', bg: 'rgba(255, 193, 7, 0.03)' }
    };
    
    if (!colors[threatLevel]) return;
    
    const color = colors[threatLevel];
    
    sensitiveInputs.forEach(input => {
        input.style.cssText += `
            border: 2px solid ${color.border} !important;
            box-shadow: 0 0 8px ${color.shadow} !important;
            background-color: ${color.bg} !important;
            animation: fieldPulse 2s ease-in-out infinite !important;
        `;
        
        // Add warning tooltip
        input.addEventListener('focus', showInputWarning);
        input.addEventListener('blur', hideInputWarning);
    });
    
    // Add CSS animation
    if (!document.getElementById('phishing-field-styles')) {
        const style = document.createElement('style');
        style.id = 'phishing-field-styles';
        style.textContent = `
            @keyframes fieldPulse {
                0%, 100% { box-shadow: 0 0 8px ${color.shadow} !important; }
                50% { box-shadow: 0 0 15px ${color.shadow} !important; }
            }
        `;
        document.head.appendChild(style);
    }
}

// Show input warning tooltip
function showInputWarning(event) {
    const input = event.target;
    const existingTooltip = document.getElementById('phishing-input-warning');
    if (existingTooltip) existingTooltip.remove();
    
    const tooltip = document.createElement('div');
    tooltip.id = 'phishing-input-warning';
    tooltip.innerHTML = `
        <div style="
            position: absolute;
            background: #dc3545;
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            z-index: 2147483647;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            animation: tooltipFadeIn 0.3s ease-out;
        ">
            ⚠️ WARNING: Do not enter sensitive information on this site!
            <div style="
                position: absolute;
                top: 100%;
                left: 50%;
                transform: translateX(-50%);
                border: 6px solid transparent;
                border-top-color: #dc3545;
            "></div>
        </div>
        <style>
            @keyframes tooltipFadeIn {
                from { opacity: 0; transform: translateY(-5px); }
                to { opacity: 1; transform: translateY(0); }
            }
        </style>
    `;
    
    // Position tooltip
    const rect = input.getBoundingClientRect();
    tooltip.style.position = 'fixed';
    tooltip.style.left = rect.left + 'px';
    tooltip.style.top = (rect.top - 50) + 'px';
    tooltip.style.zIndex = '2147483647';
    
    document.body.appendChild(tooltip);
}

// Hide input warning tooltip
function hideInputWarning() {
    const tooltip = document.getElementById('phishing-input-warning');
    if (tooltip) {
        tooltip.style.opacity = '0';
        setTimeout(() => tooltip.remove(), 200);
    }
}

// Enhanced form submission monitoring
function initializeFormMonitoring() {
    document.addEventListener('submit', handleFormSubmission, true);
    
    // Monitor dynamic forms
    const observer = new MutationObserver(mutations => {
        mutations.forEach(mutation => {
            mutation.addedNodes.forEach(node => {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    const forms = node.querySelectorAll ? node.querySelectorAll('form') : [];
                    forms.forEach(form => {
                        form.addEventListener('submit', handleFormSubmission, true);
                    });
                    
                    if (node.tagName === 'FORM') {
                        node.addEventListener('submit', handleFormSubmission, true);
                    }
                }
            });
        });
    });
    
    observer.observe(document.body, { childList: true, subtree: true });
}

// Handle form submissions with enhanced protection
function handleFormSubmission(event) {
    // Get current analysis from background script
    chrome.runtime.sendMessage({ 
        action: 'getAnalysis', 
        tabId: null 
    }, (analysis) => {
        if (analysis && analysis.result && analysis.result.prediction !== 'legitimate') {
            const form = event.target;
            
            // Check for sensitive data
            const hasSensitiveData = checkForSensitiveData(form);
            
            if (hasSensitiveData) {
                event.preventDefault();
                event.stopPropagation();
                
                showFormSubmissionWarning(analysis.result, () => {
                    // User chose to proceed
                    form.removeEventListener('submit', handleFormSubmission, true);
                    form.submit();
                });
            }
        }
    });
}

// Check if form contains sensitive data
function checkForSensitiveData(form) {
    const sensitiveSelectors = [
        'input[type="password"]',
        'input[type="email"]',
        'input[name*="card"]',
        'input[name*="credit"]',
        'input[name*="ssn"]',
        'input[name*="social"]',
        'input[name*="bank"]',
        'input[pattern*="[0-9]"]' // Likely credit card patterns
    ];
    
    return sensitiveSelectors.some(selector => 
        form.querySelector(selector) && form.querySelector(selector).value.trim()
    );
}

// Show form submission warning
function showFormSubmissionWarning(result, proceedCallback) {
    const modal = document.createElement('div');
    modal.innerHTML = `
        <div style="
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 2147483647;
            display: flex;
            align-items: center;
            justify-content: center;
            animation: modalFadeIn 0.3s ease-out;
        ">
            <div style="
                background: white;
                border-radius: 16px;
                padding: 30px;
                max-width: 500px;
                width: 90%;
                text-align: center;
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
                animation: modalSlideUp 0.3s ease-out;
            ">
                <div style="font-size: 3em; margin-bottom: 15px; color: #dc3545;">🚨</div>
                <h3 style="color: #dc3545; margin-bottom: 15px; font-size: 1.4em;">
                    STOP! Sensitive Data Detected
                </h3>
                <p style="color: #333; margin-bottom: 20px; line-height: 1.5;">
                    You are about to submit sensitive information to a ${result.prediction === 'phishing' ? 'confirmed phishing' : 'suspicious'} website. 
                    This could compromise your personal data.
                </p>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #dc3545;">
                    <strong>Detection Confidence:</strong> ${(result.confidence * 100).toFixed(1)}%<br>
                    <strong>Threat Level:</strong> ${result.prediction.toUpperCase()}
                </div>
                <div style="display: flex; gap: 15px; justify-content: center;">
                    <button onclick="this.parentElement.parentElement.parentElement.remove()" style="
                        background: #28a745;
                        color: white;
                        border: none;
                        padding: 12px 24px;
                        border-radius: 8px;
                        font-weight: 600;
                        cursor: pointer;
                        font-size: 1em;
                    ">
                        Cancel (Recommended)
                    </button>
                    <button onclick="
                        this.parentElement.parentElement.parentElement.remove();
                        (${proceedCallback.toString()})();
                    " style="
                        background: #dc3545;
                        color: white;
                        border: none;
                        padding: 12px 24px;
                        border-radius: 8px;
                        font-weight: 600;
                        cursor: pointer;
                        font-size: 1em;
                    ">
                        Submit Anyway
                    </button>
                </div>
            </div>
        </div>
        <style>
            @keyframes modalFadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
            @keyframes modalSlideUp {
                from { opacity: 0; transform: translateY(30px); }
                to { opacity: 1; transform: translateY(0); }
            }
        </style>
    `;
    
    document.body.appendChild(modal);
}

// Add floating security indicator
function addSecurityIndicator() {
    if (document.getElementById('phishing-detector-indicator')) return;
    
    const indicator = document.createElement('div');
    indicator.id = 'phishing-detector-indicator';
    indicator.innerHTML = `
        <div style="
            position: fixed;
            bottom: 25px;
            right: 25px;
            background: rgba(108, 117, 125, 0.9);
            color: white;
            padding: 10px 15px;
            border-radius: 20px;
            font-family: 'Segoe UI', sans-serif;
            font-size: 12px;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
            z-index: 2147483644;
            cursor: pointer;
            transition: all 0.3s ease;
            animation: indicatorSlideIn 0.5s ease-out;
            backdrop-filter: blur(10px);
        " onmouseover="this.style.transform='scale(1.05)'" 
           onmouseout="this.style.transform='scale(1)'"
           onclick="this.style.opacity='0'; setTimeout(() => this.remove(), 300);">
            🛡️ Analyzing...
        </div>
        <style>
            @keyframes indicatorSlideIn {
                from { opacity: 0; transform: translateY(20px); }
                to { opacity: 1; transform: translateY(0); }
            }
        </style>
    `;
    
    document.body.appendChild(indicator);
}

// Update security indicator
function updateSecurityIndicator(result) {
    const indicator = document.getElementById('phishing-detector-indicator');
    if (!indicator) return;
    
    const colors = {
        legitimate: '#28a745',
        warning: '#ffc107',  
        phishing: '#dc3545'
    };
    
    const icons = {
        legitimate: '✅',
        warning: '⚠️',
        phishing: '🚨'
    };
    
    const texts = {
        legitimate: 'Site Verified Safe',
        warning: 'Suspicious Site',
        phishing: 'Phishing Detected'
    };
    
    const color = colors[result.prediction] || '#6c757d';
    const icon = icons[result.prediction] || '?';
    const text = texts[result.prediction] || 'Unknown';
    
    indicator.innerHTML = `
        <div style="
            background: ${color};
            color: white;
            padding: 12px 16px;
            border-radius: 20px;
            font-family: 'Segoe UI', sans-serif;
            font-size: 12px;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
            cursor: pointer;
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
            display: flex;
            align-items: center;
            gap: 8px;
        " onmouseover="this.style.transform='scale(1.05)'" 
           onmouseout="this.style.transform='scale(1)'"
           onclick="this.style.opacity='0'; setTimeout(() => this.remove(), 300);">
            ${icon} ${text}
        </div>
    `;
    
    // Auto-hide for legitimate sites
    if (result.prediction === 'legitimate') {
        setTimeout(() => {
            if (indicator.parentNode) {
                indicator.style.opacity = '0';
                setTimeout(() => indicator.remove(), 300);
            }
        }, 4000);
    }
}

// Remove existing banners
function removeExistingBanners() {
    const banners = [
        'phishing-detector-banner',
        'phishing-detector-caution',
        'phishing-detector-overlay'
    ];
    
    banners.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.remove();
        }
    });
    
    // Reset body margin
    if (document.body) {
        document.body.style.marginTop = '0';
    }
}

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    removeExistingBanners();
    
    // Remove indicators
    const indicator = document.getElementById('phishing-detector-indicator');
    if (indicator) indicator.remove();
    
    // Remove styles
    const styles = document.getElementById('phishing-field-styles');
    if (styles) styles.remove();
});

// Handle visibility change (tab switching)
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
        // Re-check when tab becomes visible
        chrome.runtime.sendMessage({ action: 'contentScriptReady' }).catch(() => {
            // Background script might not be ready
        });
    }
});

console.log('Enhanced phishing detector content script loaded');