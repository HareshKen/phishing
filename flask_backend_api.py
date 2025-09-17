from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import pandas as pd
import numpy as np
import warnings
from urllib.parse import urlparse
import re
import math
from collections import Counter
import socket
import logging
from datetime import datetime
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Suppress warnings
warnings.filterwarnings("ignore")

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Global variables
model_data = None
feature_extractor = None

def is_ip_address(hostname):
    """Check if hostname is an IP address"""
    try:
        socket.inet_aton(hostname)
        return 1
    except socket.error:
        return 0

def calculate_shannon_entropy(text):
    """Calculate Shannon entropy of a string"""
    if not text:
        return 0
    counter = Counter(text)
    length = len(text)
    entropy = -sum(count/length * math.log2(count/length) for count in counter.values())
    return entropy

def get_tld_info(domain):
    """Get TLD information"""
    try:
        parts = domain.split('.')
        if len(parts) >= 2:
            return parts[-2], parts[-1], '.'.join(parts[:-2]) if len(parts) > 2 else ""
        return domain, "", ""
    except:
        return domain, "", ""

def extract_predefined_url_features(url):
    """Extract the predefined feature set from URL - same as training script"""
    features = {}
    
    # Initialize all features to 0
    feature_names = [
        'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at', 
        'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore', 'nb_tilde', 
        'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma', 
        'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 'nb_com', 
        'nb_dslash', 'http_in_path', 'https_token', 'ratio_digits_url', 
        'ratio_digits_host', 'punycode', 'port', 'tld_in_path', 
        'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains', 
        'prefix_suffix', 'random_domain', 'shortening_service', 
        'path_extension', 'nb_redirection', 'nb_external_redirection', 
        'length_words_raw', 'char_repeat', 'shortest_words_raw', 
        'shortest_word_host', 'shortest_word_path', 'longest_words_raw', 
        'longest_word_host', 'longest_word_path', 'avg_words_raw', 
        'avg_word_host', 'avg_word_path', 'phish_hints', 'domain_in_brand', 
        'brand_in_subdomain', 'brand_in_path', 'suspecious_tld', 
        'statistical_report', 'nb_hyperlinks', 'ratio_intHyperlinks', 
        'ratio_extHyperlinks', 'ratio_nullHyperlinks', 'nb_extCSS', 
        'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors', 
        'ratio_extErrors', 'login_form', 'external_favicon', 'links_in_tags', 
        'submit_email', 'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe', 
        'popup_window', 'safe_anchor', 'onmouseover', 'right_clic', 
        'empty_title', 'domain_in_title', 'domain_with_copyright', 
        'whois_registered_domain', 'domain_registration_length', 'domain_age', 
        'web_traffic', 'dns_record', 'google_index', 'page_rank'
    ]
    
    for name in feature_names:
        features[name] = 0
    
    try:
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed = urlparse(url.lower())
        hostname = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        # Basic URL features
        features['length_url'] = len(url)
        features['length_hostname'] = len(hostname)
        
        # IP address check
        features['ip'] = is_ip_address(hostname.split(':')[0])  # Remove port for IP check
        
        # Character counts
        features['nb_dots'] = url.count('.')
        features['nb_hyphens'] = url.count('-')
        features['nb_at'] = url.count('@')
        features['nb_qm'] = url.count('?')
        features['nb_and'] = url.count('&')
        features['nb_or'] = url.count('|')
        features['nb_eq'] = url.count('=')
        features['nb_underscore'] = url.count('_')
        features['nb_tilde'] = url.count('~')
        features['nb_percent'] = url.count('%')
        features['nb_slash'] = url.count('/')
        features['nb_star'] = url.count('*')
        features['nb_colon'] = url.count(':')
        features['nb_comma'] = url.count(',')
        features['nb_semicolumn'] = url.count(';')
        features['nb_dollar'] = url.count('$')
        features['nb_space'] = url.count(' ')
        
        # Specific substring counts
        features['nb_www'] = url.lower().count('www')
        features['nb_com'] = url.lower().count('.com')
        features['nb_dslash'] = url.count('//')
        
        # Protocol and path checks
        features['http_in_path'] = 1 if 'http' in path else 0
        features['https_token'] = 1 if 'https' in url.lower() and url.startswith('http://') else 0
        
        # Digit ratios
        url_digits = sum(c.isdigit() for c in url)
        features['ratio_digits_url'] = url_digits / len(url) if url else 0
        
        host_digits = sum(c.isdigit() for c in hostname)
        features['ratio_digits_host'] = host_digits / len(hostname) if hostname else 0
        
        # Punycode check
        features['punycode'] = 1 if 'xn--' in hostname else 0
        
        # Port check
        features['port'] = 1 if ':' in hostname and not hostname.startswith('www') else 0
        
        # TLD features
        domain_part, tld, subdomain = get_tld_info(hostname)
        features['tld_in_path'] = 1 if tld and tld in path else 0
        features['tld_in_subdomain'] = 1 if tld and tld in subdomain else 0
        
        # Subdomain features
        subdomains = hostname.split('.')[:-2] if len(hostname.split('.')) > 2 else []
        features['nb_subdomains'] = len(subdomains)
        features['abnormal_subdomain'] = 1 if len(subdomains) > 3 else 0
        
        # Prefix-suffix check
        features['prefix_suffix'] = 1 if '-' in domain_part else 0
        
        # Random domain check (simple heuristic)
        if domain_part:
            vowels = sum(1 for c in domain_part if c in 'aeiou')
            consonants = sum(1 for c in domain_part if c.isalpha() and c not in 'aeiou')
            features['random_domain'] = 1 if vowels == 0 and consonants > 5 else 0
        
        # URL shortening services
        shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'short.link', 
                     'is.gd', 'tiny.cc', 'adf.ly', 'shorturl.at']
        features['shortening_service'] = 1 if any(shortener in hostname for shortener in shorteners) else 0
        
        # Path extension
        path_parts = path.split('.')
        if len(path_parts) > 1:
            extension = path_parts[-1].lower()
            features['path_extension'] = 1 if extension in ['exe', 'zip', 'rar'] else 0
        
        # Redirection (simplified - would need actual HTTP requests for accuracy)
        features['nb_redirection'] = 0  # Placeholder
        features['nb_external_redirection'] = 0  # Placeholder
        
        # Word analysis
        url_words = re.findall(r'[a-zA-Z]+', url)
        if url_words:
            features['length_words_raw'] = sum(len(word) for word in url_words)
            features['shortest_words_raw'] = min(len(word) for word in url_words)
            features['longest_words_raw'] = max(len(word) for word in url_words)
            features['avg_words_raw'] = features['length_words_raw'] / len(url_words)
        
        hostname_words = re.findall(r'[a-zA-Z]+', hostname)
        if hostname_words:
            features['shortest_word_host'] = min(len(word) for word in hostname_words)
            features['longest_word_host'] = max(len(word) for word in hostname_words)
            features['avg_word_host'] = sum(len(word) for word in hostname_words) / len(hostname_words)
        
        path_words = re.findall(r'[a-zA-Z]+', path)
        if path_words:
            features['shortest_word_path'] = min(len(word) for word in path_words)
            features['longest_word_path'] = max(len(word) for word in path_words)
            features['avg_word_path'] = sum(len(word) for word in path_words) / len(path_words)
        
        # Character repetition check
        char_counts = Counter(url.lower())
        max_char_repeat = max(char_counts.values()) if char_counts else 0
        features['char_repeat'] = 1 if max_char_repeat > 3 else 0
        
        # Phishing hints
        phish_keywords = ['secure', 'verify', 'account', 'login', 'update', 'confirm', 
                         'suspend', 'urgent', 'click', 'winner', 'prize']
        features['phish_hints'] = sum(1 for word in phish_keywords if word in url.lower())
        
        # Brand analysis
        popular_brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 
                         'paypal', 'ebay', 'netflix', 'instagram', 'twitter']
        
        features['domain_in_brand'] = 0
        features['brand_in_subdomain'] = 0
        features['brand_in_path'] = 0
        
        for brand in popular_brands:
            if brand in domain_part.lower() and domain_part.lower() != brand:
                features['domain_in_brand'] = 1
            if brand in subdomain.lower():
                features['brand_in_subdomain'] = 1
            if brand in path.lower():
                features['brand_in_path'] = 1
        
        # Suspicious TLD
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
        features['suspecious_tld'] = 1 if any(tld_s in url.lower() for tld_s in suspicious_tlds) else 0
        
        # Web-based features (placeholders - would need actual web scraping)
        features['statistical_report'] = 0
        features['nb_hyperlinks'] = 0
        features['ratio_intHyperlinks'] = 0
        features['ratio_extHyperlinks'] = 0
        features['ratio_nullHyperlinks'] = 0
        features['nb_extCSS'] = 0
        features['ratio_intRedirection'] = 0
        features['ratio_extRedirection'] = 0
        features['ratio_intErrors'] = 0
        features['ratio_extErrors'] = 0
        features['login_form'] = 0
        features['external_favicon'] = 0
        features['links_in_tags'] = 0
        features['submit_email'] = 0
        features['ratio_intMedia'] = 0
        features['ratio_extMedia'] = 0
        features['sfh'] = 0
        features['iframe'] = 0
        features['popup_window'] = 0
        features['safe_anchor'] = 0
        features['onmouseover'] = 0
        features['right_clic'] = 0
        features['empty_title'] = 0
        features['domain_in_title'] = 0
        features['domain_with_copyright'] = 0
        
        # Domain registration features (placeholders)
        features['whois_registered_domain'] = 1  # Assume registered
        features['domain_registration_length'] = 365  # Default 1 year
        features['domain_age'] = np.random.randint(1, 1000)  # Placeholder
        features['web_traffic'] = np.random.randint(0, 1000000)  # Placeholder
        features['dns_record'] = 1  # Assume has DNS record
        features['google_index'] = 1  # Assume indexed
        features['page_rank'] = np.random.randint(0, 10)  # Placeholder
        
    except Exception as e:
        logger.error(f"Error parsing URL {url}: {e}")
        # Return zeros for all features in case of error
        pass
    
    return features

def load_model():
    """Load the trained model and components"""
    global model_data
    
    model_path = 'phishing_model_predefined.pkl'
    
    if not os.path.exists(model_path):
        logger.error(f"Model file not found: {model_path}")
        return False
    
    try:
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)
        
        logger.info("Model loaded successfully")
        logger.info(f"Model components: {list(model_data.keys())}")
        return True
        
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        return False

def predict_url_phishing(url):
    """Predict if a URL is phishing or legitimate using the trained model"""
    if not model_data:
        raise ValueError("Model not loaded")
    
    try:
        # Extract features
        features = extract_predefined_url_features(url)
        feature_df = pd.DataFrame([features])
        
        # Ensure all required features are present
        for col in model_data['feature_names']:
            if col not in feature_df.columns:
                feature_df[col] = 0
        
        # Reorder columns to match training data
        feature_df = feature_df[model_data['feature_names']]
        
        # Scale features
        features_scaled = model_data['scaler'].transform(feature_df)
        
        # Select features
        features_selected = model_data['selector'].transform(features_scaled)
        
        # Make prediction
        prediction = model_data['ensemble'].predict(features_selected)[0]
        probability = model_data['ensemble'].predict_proba(features_selected)[0]
        
        # Convert prediction to string
        prediction_str = 'Legitimate' if prediction == 1 else 'Phishing'
        
        return {
            'prediction': prediction_str,
            'confidence': float(max(probability)),
            'phishing_probability': float(probability[0]),
            'legitimate_probability': float(probability[1]),
            'features': features
        }
        
    except Exception as e:
        logger.error(f"Prediction error for URL {url}: {e}")
        raise ValueError(f"Prediction failed: {str(e)}")

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    if model_data:
        return jsonify({
            'status': 'healthy',
            'model_loaded': True,
            'timestamp': datetime.now().isoformat()
        }), 200
    else:
        return jsonify({
            'status': 'unhealthy',
            'model_loaded': False,
            'error': 'Model not loaded',
            'timestamp': datetime.now().isoformat()
        }), 503

@app.route('/predict', methods=['POST'])
def predict():
    """Main prediction endpoint"""
    try:
        # Get URL from request
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'URL is required in request body',
                'example': {'url': 'https://example.com'}
            }), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400
        
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        logger.info(f"Analyzing URL: {url}")
        
        # Make prediction
        result = predict_url_phishing(url)
        
        logger.info(f"Prediction for {url}: {result['prediction']} ({result['confidence']:.3f})")
        
        return jsonify(result), 200
        
    except ValueError as e:
        logger.error(f"Prediction error: {e}")
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/model-info', methods=['GET'])
def model_info():
    """Get information about the loaded model"""
    if not model_data:
        return jsonify({'error': 'Model not loaded'}), 503
    
    try:
        info = {
            'model_loaded': True,
            'feature_count': len(model_data['feature_names']),
            'selected_features': len(model_data['selected_feature_names']),
            'model_components': list(model_data.keys()),
            'sample_features': model_data['feature_names'][:10],
            'selected_feature_sample': model_data['selected_feature_names'][:10]
        }
        
        return jsonify(info), 200
        
    except Exception as e:
        logger.error(f"Error getting model info: {e}")
        return jsonify({'error': 'Error retrieving model information'}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'available_endpoints': ['/health', '/predict', '/model-info']
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    print("🚀 Starting Phishing Detection API Server...")
    print("📂 Loading trained model...")
    
    if load_model():
        print("✅ Model loaded successfully!")
        print("🌐 Server starting on http://localhost:5000")
        print("\nAvailable endpoints:")
        print("  GET  /health      - Health check")
        print("  POST /predict     - Analyze URL")
        print("  GET  /model-info  - Model information")
        print("\nExample usage:")
        print('  curl -X POST http://localhost:5000/predict \\')
        print('    -H "Content-Type: application/json" \\')
        print('    -d \'{"url": "https://example.com"}\'')
        print("\n" + "="*50)
        
        # Run the Flask app
        app.run(host='0.0.0.0', port=5000, debug=True)
    else:
        print("❌ Failed to load model. Please ensure 'phishing_model_predefined.pkl' exists.")
        print("Run the training script first to generate the model file.")
        exit(1)