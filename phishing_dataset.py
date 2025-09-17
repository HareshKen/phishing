import os
import pandas as pd
import numpy as np
import warnings
from urllib.parse import urlparse, parse_qs
import re
import math
from collections import Counter
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif
import xgboost as xgb
import lightgbm as lgb
from sklearn.neural_network import MLPClassifier
from sklearn.calibration import CalibratedClassifierCV
import pickle
import socket
import tldextract

warnings.filterwarnings("ignore")
print("🎯 Advanced Phishing URL Detection System v3.0")
print("🔄 Training with Predefined Feature Set")

# =========================
# Enhanced URL Feature Engineering with Predefined Features
# =========================

def is_ip_address(hostname):
    """Check if hostname is an IP address"""
    try:
        socket.inet_aton(hostname)
        return 1
    except socket.error:
        return 0

def get_tld_info(domain):
    """Get TLD information using tldextract"""
    try:
        extracted = tldextract.extract(domain)
        return extracted.domain, extracted.suffix, extracted.subdomain
    except:
        return domain, "", ""

def extract_predefined_url_features(url):
    """Extract the predefined feature set from URL"""
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
        
        # Web-based features (would need actual web scraping for accuracy)
        # Setting placeholders for now
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
        print(f"Error parsing URL {url}: {e}")
        # Return zeros for all features in case of error
        pass
    
    return features

def process_dataset_with_predefined_features(df, desc="Processing URLs"):
    """Process dataset with predefined feature extraction"""
    print(f"🔄 {desc}...")
    feature_list = []
    
    for i, row in df.iterrows():
        if i % 1000 == 0 and i > 0:
            print(f"   Processed {i}/{len(df)} URLs...")
        
        url = str(row['URL'])
        features = extract_predefined_url_features(url)
        feature_list.append(features)
    
    # Convert to DataFrame
    feature_df = pd.DataFrame(feature_list)
    
    # Handle missing values
    feature_df = feature_df.fillna(0)
    
    print(f"✅ Extracted {feature_df.shape[1]} predefined features from {len(df)} URLs")
    return feature_df

# =========================
# Load and Prepare Data
# =========================
print("\n📂 Loading training dataset...")

try:
    # Load the training dataset
    df = pd.read_csv("dataset_phishing.csv")
    print(f"Loaded training dataset: {df.shape[0]} URLs")
    
    # Clean the dataset
    df = df.dropna(subset=['URL', 'label']).reset_index(drop=True)
    df['label'] = df['label'].astype(int)
    
    print(f"After cleaning: {df.shape[0]} URLs")
    print(f"Label distribution: {Counter(df['label'])}")
    
    # Balance the dataset if needed
    label_counts = Counter(df['label'])
    min_class_size = min(label_counts.values())
    
    # Sample equal amounts from each class
    balanced_df = pd.concat([
        df[df['label'] == 0].sample(n=min(min_class_size, 10000), random_state=42),
        df[df['label'] == 1].sample(n=min(min_class_size, 10000), random_state=42)
    ]).reset_index(drop=True)
    
    print(f"Balanced training dataset: {balanced_df.shape[0]} URLs")
    print(f"Balanced distribution: {Counter(balanced_df['label'])}")
    
except FileNotFoundError:
    print("❌ dataset_phishing.csv not found!")
    print("Please ensure the dataset file is in the same directory as this script.")
    exit()
except Exception as e:
    print(f"❌ Error loading dataset: {e}")
    exit()

# =========================
# Prepare Test Data from Provided URL Lists
# =========================
print("\n📂 Preparing test dataset from provided URLs...")

# Legitimate URLs from the provided list
legitimate_urls = [
    'https://www.google.com', 'https://www.youtube.com', 'https://www.wikipedia.org', 'https://www.amazon.com',
    'https://www.facebook.com', 'https://www.twitter.com', 'https://www.instagram.com', 'https://www.linkedin.com',
    'https://www.microsoft.com', 'https://www.apple.com', 'https://www.github.com', 'https://stackoverflow.com',
    'https://www.reddit.com', 'https://www.nytimes.com', 'https://www.theguardian.com/international',
    'https://en.wikipedia.org/wiki/Python_(programming_language)', 'https://www.bbc.com/news', 'https://www.imdb.com',
    'https://www.netflix.com/browse', 'https://www.spotify.com/us/', 'https://www.dropbox.com/login',
    'https://www.salesforce.com', 'https://www.oracle.com/index.html', 'https://www.adobe.com/creativecloud.html',
    'https://www.nationalgeographic.com', 'https://www.nasa.gov', 'https://www.who.int', 'https://www.un.org/en/',
    'https://developer.mozilla.org/en-US/docs/Web/JavaScript', 'https://www.python.org/downloads/',
    'https://pandas.pydata.org/docs/', 'https://scikit-learn.org/stable/user_guide.html',
    'https://www.coursera.org', 'https://www.edx.org', 'https://www.udemy.com', 'https://www.espn.com',
    'https://www.cnn.com', 'https://www.forbes.com/business', 'https://www.bloomberg.com/markets',
    'https://weather.com', 'https://www.booking.com', 'https://www.airbnb.com', 'https://www.etsy.com',
    'https://www.ebay.com', 'https://www.walmart.com', 'https://www.target.com', 'https://www.bestbuy.com',
    'https://www.huffpost.com', 'https://www.wsj.com', 'https://mail.google.com', 'https://drive.google.com',
    'https://docs.google.com', 'https://calendar.google.com', 'https://translate.google.com', 'https://news.google.com',
    'https://photos.google.com', 'https://play.google.com', 'https://maps.google.com', 'https://meet.google.com',
    'https://scholar.google.com', 'https://books.google.com', 'https://finance.google.com', 'https://trends.google.com',
    'https://domains.google', 'https://cloud.google.com', 'https://firebase.google.com', 'https://analytics.google.com',
    'https://ads.google.com', 'https://workspace.google.com', 'https://www.office.com', 'https://outlook.live.com',
    'https://onedrive.live.com', 'https://teams.microsoft.com', 'https://azure.microsoft.com', 'https://code.visualstudio.com',
    'https://www.bing.com', 'https://www.msn.com', 'https://www.xbox.com', 'https://www.skype.com/en/',
    'https://www.icloud.com', 'https://music.apple.com', 'https://tv.apple.com', 'https://www.apple.com/maps',
    'https://developer.apple.com', 'https://support.apple.com', 'https://www.beatsbydre.com', 'https://aws.amazon.com',
    'https://www.twitch.tv', 'https://www.audible.com', 'https://www.goodreads.com', 'https://www.zappos.com',
    'https://www.wholefoodsmarket.com', 'https://www.abebooks.com', 'https://www.shopbop.com', 'https://www.woot.com',
    'https://www.alexa.com', 'https://www.comixology.com', 'https://www.boxofficemojo.com', 'https://www.dpreview.com',
    'https://fabric.com', 'https://www.slack.com', 'https://www.zoom.us', 'https://www.notion.so', 'https://www.trello.com',
    'https://www.atlassian.com/software/jira', 'https://bitbucket.org', 'https://confluence.atlassian.com', 'https://about.gitlab.com',
    'https://www.docker.com', 'https://kubernetes.io', 'https://www.ansible.com', 'https://www.terraform.io',
    'https://www.vagrantup.com', 'https://www.jenkins.io', 'https://grafana.com', 'https://prometheus.io',
    'https://www.elastic.co', 'https://www.mongodb.com', 'https://www.postgresql.org', 'https://www.mysql.com',
    'https://redis.io', 'https://www.sqlite.org/index.html', 'https://www.apache.org', 'https://www.nginx.com',
    'https://httpd.apache.org', 'https://www.gnu.org', 'https://www.linux.org', 'https://www.kernel.org',
    'https://www.ubuntu.com', 'https://www.debian.org', 'https://www.redhat.com/en', 'https://getfedora.org',
    'https://www.centos.org', 'https://archlinux.org', 'https://www.djangoproject.com', 'https://rubyonrails.org',
    'https://flask.palletsprojects.com', 'https://fastapi.tiangolo.com', 'https://expressjs.com', 'https://nodejs.org',
    'https://www.npmjs.com', 'https://yarnpkg.com', 'https://webpack.js.org', 'https://babeljs.io',
    'https://reactjs.org', 'https://angular.io', 'https://vuejs.org', 'https://svelte.dev',
    'https://jquery.com', 'https://getbootstrap.com', 'https://tailwindcss.com', 'https://sass-lang.com',
    'https://www.typescriptlang.org', 'https://gohugo.io', 'https://jekyllrb.com', 'https://www.gatsbyjs.com',
    'https://nextjs.org', 'https://nuxtjs.org', 'https://www.electronjs.org', 'https://flutter.dev',
    'https://reactnative.dev', 'https://kotlinlang.org', 'https://www.swift.org', 'https://golang.org',
    'https://www.rust-lang.org', 'https://www.php.net', 'https://www.perl.org', 'https://www.ruby-lang.org/en/',
    'https://www.java.com', 'https://www.cplusplus.com', 'https://docs.microsoft.com/en-us/dotnet/csharp/', 'https://isocpp.org',
    'https://www.reuters.com', 'https://www.apnews.com', 'https://www.aljazeera.com', 'https://www.dw.com',
    'https://www.france24.com/en/', 'https://www.npr.org', 'https://www.pbs.org', 'https://www.c-span.org',
    'https://www.latimes.com', 'https://www.chicagotribune.com', 'https://www.bostonglobe.com', 'https://www.sfchronicle.com',
    'https://www.washingtonpost.com', 'https://time.com', 'https://www.newyorker.com', 'https://www.theatlantic.com',
    'https://www.wired.com', 'https://www.vox.com', 'https://www.theverge.com', 'https://techcrunch.com',
    'https://arstechnica.com', 'https://gizmodo.com', 'https://www.engadget.com', 'https://mashable.com',
    'https://www.cnet.com', 'https://www.zdnet.com', 'https://venturebeat.com', 'https://www.polygon.com',
    'https://kotaku.com', 'https://www.ign.com', 'https://www.gamespot.com', 'https://www.rockpapershotgun.com',
    'https://www.euronews.com', 'https://www.ft.com', 'https://www.economist.com', 'https://foreignpolicy.com',
    'https://www.scientificamerican.com', 'https://www.nature.com', 'https://www.sciencemag.org', 'https://www.cell.com',
    'https://www.thelancet.com', 'https://www.nejm.org', 'https://www.bmj.com', 'https://jamanetwork.com',
    'https://www.plos.org', 'https://arxiv.org', 'https://www.jstor.org', 'https://www.academia.edu',
    'https://www.researchgate.net', 'https://www.mendeley.com', 'https://www.grammarly.com', 'https://www.turnitin.com',
    'https://www.overleaf.com', 'https://www.mit.edu', 'https://www.harvard.edu', 'https://www.stanford.edu',
    'https://www.berkeley.edu', 'https://www.cam.ac.uk', 'https://www.ox.ac.uk', 'https://www.ethz.ch/en.html',
    'https://www.caltech.edu', 'https://www.uchicago.edu', 'https://www.princeton.edu', 'https://www.yale.edu',
    'https://www.columbia.edu', 'https://www.ucl.ac.uk', 'https://www.imperial.ac.uk', 'https://www.utoronto.ca',
    'https://www.ubc.ca', 'https://www.mcgill.ca', 'https://www.anu.edu.au', 'https://www.unimelb.edu.au',
    'https://www.usyd.edu.au', 'https://www.uq.edu.au', 'https://www.tsinghua.edu.cn/en/', 'https://www.pku.edu.cn/en/',
    'https://www.nus.edu.sg', 'https://www.ntu.edu.sg', 'https://www.gov.uk', 'https://www.whitehouse.gov',
    'https://www.canada.ca/en.html', 'https://www.australia.gov.au', 'https://www.india.gov.in', 'https://www.bundesregierung.de/breg-de',
    'https://www.gouvernement.fr', 'https://www.japan.go.jp', 'https://english.www.gov.cn', 'https://www.europa.eu',
    'https://www.cia.gov', 'https://www.fbi.gov', 'https://www.irs.gov', 'https://www.sec.gov',
    'https://www.nih.gov', 'https://www.cdc.gov', 'https://www.fda.gov', 'https://www.epa.gov',
    'https://www.uspto.gov', 'https://www.loc.gov', 'https://www.archives.gov', 'https://www.si.edu',
    'https://www.nps.gov', 'https://www.usgs.gov', 'https://www.noaa.gov', 'https://www.ecb.europa.eu/home/html/index.en.html',
    'https://www.federalreserve.gov', 'https://www.imf.org', 'https://www.worldbank.org', 'https://www.oecd.org',
    'https://www.wto.org', 'https://www.weforum.org', 'https://www.redcross.org', 'https://www.doctorswithoutborders.org',
    'https://www.amnesty.org', 'https://www.hrw.org', 'https://www.greenpeace.org', 'https://www.worldwildlife.org',
    'https://www.paypal.com', 'https://www.stripe.com', 'https://www.squareup.com', 'https://www.visa.com',
    'https://www.mastercard.com', 'https://www.americanexpress.com', 'https://www.discover.com', 'https://www.bankofamerica.com',
    'https://www.jpmorganchase.com', 'https://www.wellsfargo.com', 'https://www.citi.com', 'https://www.usbank.com',
    'https://www.capitalone.com', 'https://www.pnc.com', 'https://www.td.com', 'https://www.schwab.com',
    'https://www.fidelity.com', 'https://www.vanguard.com', 'https://www.blackrock.com/corporate', 'https://www.morganstanley.com',
    'https://www.goldmansachs.com', 'https://www.hsbc.com', 'https://www.barclays.com', 'https://www.lloydsbank.com',
    'https://www.ubs.com/global/en.html', 'https://group.credit-suisse.com', 'https://www.db.com', 'https://www.dhl.com',
    'https://www.fedex.com', 'https://www.ups.com', 'https://www.usps.com', 'https://www.royalmail.com',
    'https://www.canadapost.ca', 'https://auspost.com.au', 'https://www.deutschepost.de/en/home.html', 'https://www.laposte.fr',
    'https://www.expedia.com', 'https://www.kayak.com', 'https://www.tripadvisor.com', 'https://www.hertz.com',
    'https://www.enterprise.com/en/home.html', 'https://www.marriott.com', 'https://www.hilton.com', 'https://www.ihg.com',
    'https://www.hyatt.com', 'https://www.accor.com', 'https://www.united.com', 'https://www.aa.com',
    'https://www.delta.com', 'https://www.southwest.com', 'https://www.britishairways.com', 'https://www.lufthansa.com/us/en/homepage',
    'https://www.airfrance.us', 'https://www.emirates.com', 'https://www.qatarairways.com', 'https://www.singaporeair.com',
    'https://www.cathaypacific.com', 'https://www.qantas.com', 'https://www.aircanada.com', 'https://www.ana.co.jp/en/us/',
    'https://www.jal.co.jp/en/', 'https://www.klm.com', 'https://www.spotify.com', 'https://www.pandora.com',
    'https://soundcloud.com', 'https://www.bandcamp.com', 'https://www.hulu.com', 'https://www.disneyplus.com',
    'https://www.hbomax.com', 'https://www.peacocktv.com', 'https://www.paramountplus.com', 'https://www.vudu.com',
    'https://tubitv.com', 'https://pluto.tv', 'https://www.crunchyroll.com', 'https://www.funimation.com',
    'https://www.vimeo.com', 'https://www.dailymotion.com', 'https://www.flickr.com', 'https://www.pinterest.com',
    'https://www.tumblr.com', 'https://www.medium.com', 'https://www.quora.com', 'https://www.stackoverflow.com',
    'https://www.askubuntu.com', 'https://serverfault.com', 'https://superuser.com', 'https://www.instructables.com',
    'https://www.wikihow.com', 'https://www.khanacademy.org', 'https://www.codecademy.com', 'https://www.freecodecamp.org',
    'https://www.pluralsight.com', 'https://www.lynda.com', 'https://www.skillshare.com', 'https://www.masterclass.com',
    'https://www.duolingo.com', 'https://www.rosettastone.com', 'https://www.memrise.com', 'https://www.ted.com',
    'https://www.kickstarter.com', 'https://www.indiegogo.com', 'https://www.patreon.com', 'https://www.gofundme.com',
    'https://www.charitynavigator.org', 'https://www.givewell.org', 'https://www.craigslist.org', 'https://www.rotten-tomatoes.com',
    'https://www.metacritic.com', 'https://www.allmusic.com', 'https://www.discogs.com', 'https://www.last.fm',
    'https://www.billboard.com', 'https://www.pitchfork.com', 'https://www.rollingstone.com', 'https://variety.com',
    'https://www.hollywoodreporter.com', 'https://deadline.com', 'https://www.espncricinfo.com', 'https://www.cbssports.com',
    'https://bleacherreport.com', 'https://www.sbnation.com', 'https://theathletic.com', 'https://www.nba.com',
    'https://www.nfl.com', 'https://www.mlb.com', 'https://www.nhl.com', 'https://www.mls.com',
    'https://www.premierleague.com', 'https://www.uefa.com', 'https://www.fifa.com', 'https://www.olympic.org',
    'https://www.formula1.com', 'https://www.motogp.com', 'https://www.nascar.com', 'https://www.wwe.com',
    'https://www.ufc.com', 'https://www.homedepot.com', 'https://www.lowes.com', 'https://www.ikea.com',
    'https://www.wayfair.com', 'https://www.overstock.com', 'https://www.zillow.com', 'https://www.realtor.com',
    'https://www.redfin.com', 'https://www.trulia.com', 'https://www.apartments.com', 'https://www.costco.com',
    'https://www.samsclub.com', 'https://www.kroger.com', 'https://www.albertsons.com', 'https://www.publix.com',
    'https://www.wholefoodsmarket.com', 'https://www.traderjoes.com', 'https://www.instacart.com', 'https://www.doordash.com',
    'https://www.grubhub.com', 'https://www.ubereats.com', 'https://www.lyft.com', 'https://www.uber.com',
    'https://www.cvs.com', 'https://www.walgreens.com', 'https://www.riteaid.com', 'https://www.webmd.com',
    'https://www.mayoclinic.org', 'https://my.clevelandclinic.org', 'https://www.hopkinsmedicine.org', 'https://www.healthline.com',
    'https://www.medscape.com', 'https://www.goodrx.com', 'https://www.consumerreports.org', 'https://www.bbb.org',
    'https://www.glassdoor.com', 'https://www.indeed.com', 'https://www.monster.com', 'https://www.ziprecruiter.com',
    'https://angel.co', 'https://www.crunchbase.com', 'https://www.producthunt.com', 'https://news.ycombinator.com',
    'https://www.behance.net', 'https://dribbble.com', 'https://www.artstation.com', 'https://deviantart.com',
    'https://500px.com', 'https://unsplash.com', 'https://pixabay.com', 'https://www.pexels.com',
    'https://www.canva.com', 'https://www.figma.com', 'https://www.sketch.com', 'https://www.invisionapp.com',
    'https://www.marvelapp.com', 'https://www.framer.com', 'https://webflow.com', 'https://www.squarespace.com',
    'https://www.wix.com', 'https://www.shopify.com', 'https://www.bigcommerce.com', 'https://www.magento.com',
    'https://wordpress.org', 'https://wordpress.com', 'https://www.joomla.org', 'https://www.drupal.org',
    'https://www.godaddy.com', 'https://www.namecheap.com', 'https://domains.google', 'https://www.bluehost.com',
    'https://www.hostgator.com', 'https://www.siteground.com', 'https://www.wpengine.com', 'https://www.digitalocean.com',
    'https://www.linode.com', 'https://www.vultr.com', 'https://www.heroku.com', 'https://www.netlify.com',
    'https://vercel.com', 'https://www.cloudflare.com', 'https://www.akamai.com', 'https://www.fastly.com',
    'https://www.intuit.com/turbotax/', 'https://www.hrblock.com', 'https://www.quickbooks.intuit.com', 'https://www.xero.com',
    'https://www.freshbooks.com', 'https://www.waveapps.com', 'https://www.expensify.com', 'https://www.surveymonkey.com',
    'https://www.typeform.com', 'https://www.google.com/forms/about/', 'https://www.mailchimp.com', 'https://www.constantcontact.com',
    'https://www.sendgrid.com', 'https://www.twilio.com', 'https://www.cisco.com', 'https://www.ibm.com',
    'https://www.intel.com', 'https://www.amd.com', 'https://www.nvidia.com', 'https://www.qualcomm.com',
    'https://www.samsung.com', 'https://www.lg.com', 'https://www.sony.com', 'https://www.panasonic.com',
    'https://www.dell.com', 'https://www.hp.com', 'https://www.lenovo.com', 'https://www.asus.com',
    'https://www.acer.com', 'https://www.logitech.com', 'https://www.razer.com', 'https://www.corsair.com',
    'https://www.seagate.com', 'https://www.westerndigital.com', 'https://www.kingston.com', 'https://www.sandisk.com',
    'https://www.tesla.com', 'https://www.ford.com', 'https://www.gm.com', 'https://www.toyota.com',
    'https://www.honda.com', 'https://www.nissanusa.com', 'https://www.volkswagen.com', 'https://www.bmwusa.com',
    'https://www.mercedes-benz.com', 'https://www.audiusa.com', 'https://www.porsche.com', 'https://www.ferrari.com',
    'https://www.lamborghini.com', 'https://www.boeing.com', 'https://www.airbus.com', 'https://www.lockheedmartin.com',
    'https://www.northropgrumman.com', 'https://www.raytheon.com', 'https://www.spacex.com', 'https://www.blueorigin.com',
    'https://www.virgingalactic.com', 'https://www.disney.com', 'https://www.warnerbros.com', 'https://www.universalpictures.com',
    'https://www.paramount.com', 'https://www.sonypictures.com', 'https://www.netflix.com', 'https://www.hbo.com',
    'https://www.rottentomatoes.com', 'https://www.allrecipes.com', 'https://www.foodnetwork.com', 'https://www.epicurious.com',
    'https://www.simplyrecipes.com', 'https://www.yummly.com'
]

phishing_urls = [
    'http://secure-login-update.com-apple.tk/verify', 'http://paypal.com.confirm-account.net/webscr?cmd=_login-run',
    'https://amazon-support-service.ga/customer/update?id=12345', 'http://192.168.1.1/admin.html',
    'https://microsoft-office365-support.cf/login/', 'http://bankofamerica.com.security-alert.info/login.php',
    'https://chase-online-banking.gq/verify/personal-details', 'http://wells-fargo-update-required.ml/auth/login',
    'https://login.google.com.accounts.security.info-check.ru/signin', 'http://tinyurl.com/y3xZabc9',
    'https://apple-id-support-team.com-service.io/recover', 'http://facebook-security-check.info/login?next=home',
    'https://your-package-tracking-dhl.info/track/1Z999AA10123456784', 'http://irs-gov-tax-refund.com/submit-form',
    'http://dropbox-shared-file-access.link/download/document.zip', 'https://netflix-account-suspended.org/reactivate',
    'http://update-your-browser-for-security.com/chrome.exe', 'http://bit.ly/3kXyz123',
    'https://verify-your-identity-immediately.com/amazon-prime', 'http://203.0.113.45/wp-admin/login.php',
    'https://accounts-google-com-sign-in-session.me/ServiceLogin', 'http://login-microsoftonline.com-security.co/',
    'https://yourbank.com.update.details.now.info/', 'http://hsbc-online-banking-secure.org/login.htm',
    'https://secure-message-center.com-att.net/read?msg_id=98765', 'http://fedex-delivery-notification.info/tracking.js',
    'http://ebay-resolution-center-case-pp-123.com/signin', 'https://craigslist-support-team-alert.org/posts',
    'http://americanexpress.com.verify.card.info/myca/logon.do', 'https://secure.payment-update-mastercard.com/process',
    'http://aol-mail-login-recovery.com/account/auth', 'https://customer-support-alert-linkedin.com/feed/',
    'http://bank-of-scotland-online.com/security/login-check.html', 'https://webmail-godaddy-secure.com/login.php',
    'http://instagram-password-reset-tool.com/reset', 'http://t-mobile-bill-payment-due.com/pay',
    'http://verizon-wireless-support-account.net/my-verizon', 'http://westernunion-money-transfer-alert.com/track',
    'https://secure-icloud-login-find-my-iphone.com/auth', 'http://usps-package-delivery-failed.info/redelivery',
    'https://twitter-account-suspended-appeal.com/form', 'http://google-drive-shared-with-me.link/doc/1234',
    'https://whatsapp-verification-code-required.com/verify-now', 'http://capital-one-security-update.net/login',
    'https://citibank-online-fraud-detection.org/signon', 'http://discover-card-services-account.com/portal/login',
    'https://suntrust-bank-online-security.com/login.php', 'http://usbank.com-online-banking-alerts.info/login',
    'http://amazon-prime-rewards-claim.top/winner', 'https://secure-wellsfargo-online.net/login/auth',
    'http://appleid.apple.com-verify-account.info/manage', 'https://login-google-drive.com-share.cf/files/document.pdf',
    'http://facebook-com-security-notice.ga/login-approval.php', 'https://paypal-transaction-dispute.gq/resolution-center/',
    'http://microsoft-account-unusual-activity.ml/signin/office365', 'http://185.125.190.45/boa/login.html',
    'https://your-dhl-parcel-is-waiting.link/track?id=45321', 'http://irs.gov.tax-return-online.com/efile/submit',
    'https://netflix.com-login-help.io/account/recover', 'http://secure-chase-bank-online-services.info/verify',
    'https://accounts.google.com.confirm-email.ru/ServiceLogin?service=mail', 'http://adobe-creative-cloud-update.tk/install/flashplayer.exe',
    'https://dropbox-file-shared-notification.org/view/important-document', 'http://ebay.com-account-limitations.net/ws/eBayISAPI.dll',
    'https://icloud.com-find-my-iphone-location.com/login/', 'http://linkedin-com-account-alert.co/profile/security-check',
    'https://secure-site-hsbc-uk.com/1/2/login.aspx', 'http://usps.com.package-held-for-pickup.info/tracking-details',
    'https://amazon-prime-video-billing-update.com/my-account', 'http://bit.ly/secure-login-page',
    'https://www.dropbox-sharedfiles.com/d/s/1a2b3c4d5e/Financials.zip', 'http://bankofamerica-secure-messaging.com/inbox/alert',
    'https://appleid-manage-account-security.org/iforgot/password', 'http://fedex-package-delivery-update.link/track/shipment',
    'https://login-microsoft-online-services.net/common/oauth2/authorize', 'http://facebook.com.profile-lock.info/confirm/identity',
    'https://secure-online-banking-citibank.com/login/user', 'http://tinyurl.com/office365-login-portal',
    'http://wells-fargo-online-secure-session.org/signon/validate', 'https://google-docs-secure-sharing.com/document/view/123',
    'http://172.104.249.78/apple-icloud-login/', 'https://your-netflix-account-is-on-hold.com/billing/update-payment',
    'http://paypal.com.secure-transaction-details.xyz/webapps/mpp/home', 'https://twitter-help-center-recovery.com/account/reset',
    'https://amazon-order-confirmation-details.com/gp/your-account/', 'http://blockchain-wallet-verification.info/login',
    'https://coinbase-pro-secure-login.com/auth/new-device', 'http://dhl-express-shipment-tracking.net/track/parcel',
    'https://instagram-com-support.help-center.io/login-issue', 'http://irs-tax-refund-status-online.org/get/refund',
    'https://linkedin.com.secure-messaging.net/inbox/view', 'http://microsoft-onedrive-file-share.com/view.aspx?file=report.docx',
    'https://verizon-wireless-bill-overdue.com/my-verizon/pay-bill', 'http://usps-shipping-label-info.com/print/label',
    'https://support-apple-com-account-recovery.net/iforgot', 'http://bankofamerica.com-login-portal.org/e-banking/',
    'https://chase-online-banking-verification.info/enroll/identify', 'http://google-mail-login-security.com/accounts/signin',
    'https://facebook-com-login-identify.me/login.php', 'http://netflix-billing-information-update.com/login/user',
    'https://secure-login-paypal-account.com/cgi-bin/webscr', 'http://104.236.46.221/wordpress/wp-login.php',
    'https://amazon-com-account-suspended.info/appeal/reactivate', 'http://apple-id-verification-center.com/iforgot/question',
    'https://dropbox-secure-file-transfer.link/s/abc123xyz', 'http://ebay-resolution-center-case.com/signin/case-details',
    'https://icloud-account-storage-full.com/manage/upgrade', 'http://linkedin-account-security-alert.org/feed/notification',
    'https://microsoft-office365-secure-login.net/login.srf', 'http://wells-fargo-security-check.com/auth/login',
    'https://google-security-alert-unusual-signin.com/accounts/recovery', 'http://att-com-bill-payment-online.net/myatt/paybill',
    'https://comcast-xfinity-account-update.com/my-account/login', 'http://docusign-secure-document-review.com/view/document',
    'https://godaddy-domain-services-login.com/dcc/login', 'http://instagram-help-center-password.com/accounts/password/reset',
    'https://my-usps-package-redelivery.com/track/redeliver', 'http://t-mobile-account-login-secure.com/my-t-mobile/home',
    'https://twitter-security-alert-login.com/i/flow/login', 'http://adobe-account-sign-in-required.com/auth/login',
    'https://americanexpress-online-services-login.com/myca/logon', 'http://aol-mail-security-update.com/login/en-us',
    'https://capitalone-360-secure-signin.com/login/init', 'http://citibank-online-account-access.org/login.do',
    'https://coinbase-wallet-security-update.link/wallet/login', 'http://costco-online-order-status.com/account/login',
    'https://discover-card-account-center.net/cardmembersvcs/acvan/login', 'http://etsy-shop-manager-login.com/signin',
    'https://irs-gov-efile-tax-return.info/file/login', 'http://mcafee-security-subscription-renewal.com/renew/login',
    'https://norton-antivirus-renewal-center.com/login/renew', 'http://slack-workspace-invitation-link.com/join/workspace',
    'https://spotify-premium-payment-failed.com/account/subscription', 'http://steam-community-trade-offer.com/tradeoffer/new/',
    'https://suntrust-online-banking-login.net/login/auth', 'http://target-redcard-account-management.com/login',
    'https://turbotax-intuit-login-account.com/signin/turbotax', 'https://uber-trip-receipt-details.com/ride/details',
    'https://ups-mychoice-delivery-alert.com/track/pkg', 'http://usbank-online-banking-security.org/login/logon',
    'https://walmart-order-shipping-update.com/account/track', 'http://whatsapp-account-verification-required.com/verify/phone',
    'https://yahoo-mail-account-security.info/login/auth', 'http://zoom-meeting-invitation-secure.com/j/1234567890',
    'https://login-apple-icloud-com.me/findmyiphone', 'http://secureserver-godaddy-webmail.com/login.php?realm=pass',
    'http://www.facebook-login-page.ga/recover/password', 'https://amazon-prime-membership-rewards.gq/claim/prize',
    'http://secure-chaseonline-jpmorgan.cf/login/verify-identity', 'https://account-google-com-services.ml/signin/v2/identifier',
    'http://icloud-mail-login.com-apple.tk/auth/login.html', 'https://microsoft.office365.login-portal.io/common/login',
    'http://paypal-com-secure-login.co/webapps/mpp/signin', 'http://wellsfargo-update-account-info.net/online-banking/sign-on',
    'https://bankofamerica-sign-in-online.com/login/secure', 'http://usps-track-package-delivery.info/details/tracking',
    'https://login.microsoftonline.com-auth.link/common/oauth2/v2.0/authorize', 'http://fedex-shipping-invoice.org/view/invoice.pdf',
    'https://apple-id-account-locked-alert.com/iforgot/unlock', 'http://amazon-aws-console-login.com/signin',
    'https://dropbox-shared-folder-invitation.com/acc/check', 'http://google-drive-document-share.net/file/d/1aBcDeFgHiJkLmNoP',
    'https://netflix-account-reactivation-needed.org/login/user', 'http://ebay-security-center-update.com/sign-in',
    'https://linkedin-profile-view-notification.com/profile/view', 'http://instagram-direct-message-login.com/direct/inbox',
    'https://twitter-password-reset-confirm.com/account/begin_password_reset', 'http://bit.ly/amazon-special-offer-2025',
    'http://tinyurl.com/apple-support-chat-now', 'https://facebook-com-friends-recommendation.me/friends/center',
    'http://irs-tax-refund-form-w2.com/submit', 'https://secure-online-payment-mastercard.net/process/transaction',
    'http://dhl-express-shipment-on-hold.com/track/release', 'http://198.54.117.211/googledocs/login.php',
    'https://capitalone-account-security-alert.org/login/validate', 'http://discover-cashback-bonus-reward.com/account/center',
    'https://americanexpress-membership-rewards.info/login', 'http://hsbc-net-banking-services.com/login/auth',
    'https://citi-online-fraud-prevention.com/signon.do', 'http://t-mobile-bill-is-ready-to-view.net/mytmobile/bill',
    'https://verizon-cloud-storage-full.com/my-verizon/cloud', 'http://att-uverse-account-login.com/olam/login.olamexecute',
    'https://comcast-business-services-login.com/login', 'http://adobe-id-sign-in-page.com/account/sign-in',
    'https://apple-developer-account-login.com/membercenter/login.action', 'https://aws-amazon-billing-alert.com/billing/home',
    'https://godaddy-workspace-email-login.com/login.aspx', 'http://indeed-job-alert-notification.com/viewjob',
    'https://lastpass-vault-security-challenge.com/login.php', 'http://my-usps-informed-delivery.org/go/login',
    'https://onedrive-live-com-file-sharing.net/view.aspx', 'http://slack-magic-link-login.com/sso/magic',
    'https://spotify-account-password-reset.info/password-reset', 'http://steam-account-recovery-support.com/help/wizard',
    'https://teamviewer-remote-session-login.com/LogOn', 'https://turbotax-account-locked-intuit.com/login/auth',
    'http://ups-delivery-attempt-notification.link/track/reschedule', 'https://xfinity-comcast-email-login.com/login',
    'http://yahoo-account-unusual-activity.co/login/challenge', 'https://zoom-us-webinar-registration.org/webinar/register',
    'https://accounts-google-verify-identity.com/signin/v2/challenge', 'http://bankofamerica-mobile-banking-app.com/login',
    'https://chase-credit-card-rewards.net/merrick/enroll/identify', 'https://facebook-messenger-secure-login.com/login/reauth',
    'https://icloud-photos-shared-album.com/us/album', 'https://login-microsoftonline-portal-azure.com/common/login',
    'https://netflix-subscription-problem.com/YourAccount', 'https://paypal-money-received-notification.org/activity',
    'http://apple-support-invoice-receipt.com/view/receipt', 'https://amazon-seller-central-login.com/ap/signin',
    'http://dropbox-business-admin-login.com/admin/login', 'https://ebay-message-center-alert.info/ws/eBayISAPI.dll',
    'https://google-ads-account-suspended.com/ads/login', 'http://linkedin-invitation-to-connect.com/in/invite',
    'https://microsoft-teams-meeting-join.com/v2/', 'http://wellsfargo-online-banking-fraud-alert.com/signon',
    'https://twitter-suspicious-login-attempt.org/login/error', 'https://www.googles-mail.com/inbox/313',
    'http://www.pay-pal.com/login-secure/index.html', 'https://www.microsfot.com/office/login',
    'http://www.appie.com/store/account-update/', 'https://www.amazoon.com/gp/css/order-history',
    'http://www.faceboook.com/security/login-check', 'https://www.netfiix.com/billing/update-payment',
    'http://www.wellfargo.com/login/sign-on', 'https://www.bancofamerica.com/secure-login/online-id',
    'http://www.gmaiil.com/account/recover', 'https://www.linkdin.com/feed/update-profile',
    'http://chase-com.online-banking.info/login', 'https://apple-com.id-verification.net/manage',
    'http://google-com.account-services.org/security', 'https://paypal-com.transaction-review.co/resolution',
    'http://bankofamerica-com.secure-messaging.xyz/inbox', 'https://microsoft-com.office365-login.me/auth',
    'http://netflix-com.account-hold.top/billing', 'https://amazon-com.order-issue.link/your-orders',
    'http://facebook-com.account-disabled.ga/help', 'https://wellsfargo-com.fraud-alert.gq/login',
    'http://amex-card-verify.com-americanexpress.biz/myca/logon', 'https://login-services-intuit-quickbooks.com/login',
    'http://account-verify-square-cash-app.com/login', 'https://alert.discovercard.com-servicing-account.net/portal/login',
    'http://secure.usaa.com-login-portal.org/login/logon', 'https://online-banking-pnc-com.info/login',
    'http://auth-tdbank-login-secure.com/login', 'https://fidelity-investments-netbenefits.com-login.co/login',
    'http://schwab-client-center-login.com/login', 'https://vanguard-investor-login.net/home/logon',
    'http://transferwise-secure-login.com/login', 'https://venmo-account-activity.com/login',
    'http://zelle-payment-notification.org/pay/receive', 'https://ally-bank-online-services.com/login',
    'http://antivirus-scan-detected-threats.com/remove-virus.exe', 'https://your-computer-is-at-risk.info/update-software',
    'http://windows-defender-alert-action-required.link/scan', 'https://flash-player-update-required.org/install.php',
    'http://java-runtime-critical-update.net/download/jre.msi', 'https://bitcoin-giveaway-2025-elon-musk.com/claim',
    'http://ethereum-wallet-sync-error.com/login', 'https://free-crypto-airdrop-claim-now.xyz/wallet',
    'http://urgent-message-from-your-ceo.com/task/wire-transfer.pdf', 'https://hr-department-policy-update.net/view/document.html',
    'http://invoice-payment-due-immediately.org/pay/invoice-12345', 'https://job-offer-remote-work-opportunity.com/apply-now',
    'http://you-have-won-a-lottery.info/claim-your-prize', 'https://dating-site-new-match-alert.com/profile/view',
    'http://pharmacy-discount-offer-viagra.biz/order', 'https://online-casino-free-spins.top/play-now',
    'http://weight-loss-secret-revealed.me/learn-more', 'https://get-rich-quick-investment-scheme.ga/register',
    'http://192.168.0.1/cgi-bin/login.ha', 'http://10.0.0.1/router/login.asp', 'http://1.1.1.1-cloudflare.com/dns-settings',
    'https://98.137.11.233/yahoo/mail/login', 'http://172.217.14.238/google/accounts/signin', 'http://com-google-accounts-support.xyz/recovery/options',
    'http://login.apple.id.me.com.az.ru/account', 'https://secure-login.bankofamerica.com-net.info/homepage',
    'http://ebay-com.pp-case-resolution.com/signin_case', 'http://icloud-mail.com.services.ly/login/auth',
    'http://linkedin.com.messanger.me/inbox/read', 'http://www.app1e.com/support/verify', 'http://faceb00k.com/login/auth',
    'http://microsftonline.com/login.srf', 'http://paypa1.com/cgi-bin/webscr?cmd=_login-run', 'http://amzn.com-support.us/update',
    'https://googledrive.com-share-file.link/doc/1Bgt56Yh', 'http://wellsfargo-securelogin.com-auth.net/login',
    'http://citi-bank-online.com-verify.org/signon', 'https://chase-online.com-jp-morgan.info/login/access',
    'http://us-bank-online.com-login-secure.co/logon', 'https://capital-one-360.com-account.net/login',
    'http://american-express.com-cards.org/myca/logon', 'http://discovercard.com-account.me/login/center',
    'http://hsbc-bank-uk.com-online.xyz/login/entry', 'http://verizonwireless.com-myaccount.link/login',
    'http://t-mobile.com-account-billing.top/paybill', 'http://att-login.com-my-uverse.ga/signin',
    'http://dhl-tracking.com-shipment-info.gq/track', 'http://fedex-package.com-delivery-status.cf/details',
    'http://ups-deliveries.com-mychoice-login.ml/track', 'http://usps-tracking.com-redelivery.tk/schedule',
    'https://adobe-creative-cloud.com-login.io/auth', 'http://dropbox-login.com-secure-files.co/home',
    'http://instagram-login.com-direct-message.ru/inbox', 'http://spotify-premium.com-payment-update.info/billing',
    'http://twitter-login.com-security-check.net/login', 'http://netflix.com.update.billing.info.az.ru/login',
    'http://appleid.apple.com.manage.iforgot.az.ru/passwordreset', 'https://login-google-account-services-mail.com.az.ru/signin',
    'http://secure.paypal.com.webapps.mpp.logins.az.ru/cgi-bin/webscr', 'http://account-microsoft-live-services.com.az.ru/login',
    'https://bankofamerica.com.sign-in-online-banking.az.ru/login', 'http://chase.com.online-banking-services.com.az.ru/logon',
    'http://wellsfargo.com.online-services-login.com.az.ru/auth', 'https://facebook.com.login-identify-account.com.az.ru/login',
    'http://amazon.com.your-order-has-been-dispatched.az.ru/gp/css/summary', 'https://www.linkedin.com.security.login-check.az.ru/uas/login',
    'https://www.dropbox.com.shared.file.document.az.ru/login', 'http://ebay.com.account-update-required.com.az.ru/signin',
    'http://www.icloud.com.find.my.iphone.activation.az.ru/login', 'https://www.instagram.com.password.reset.request.az.ru/accounts/login',
    'https://www.netflix.com.your.account.is.on.hold.az.ru/login', 'http://www.twitter.com.account.suspended.appeal.az.ru/login/error',
    'http://login.yahoo.com.mail.security.update.az.ru/login', 'https://wordpress.com.login.to.your.site.az.ru/wp-login.php',
    'https://www.youtube.com.account.termination.notice.az.ru/login', 'https://www.whatsapp.com.verification.code.required.az.ru/verify',
    'http://www.google.com.docs.shared.with.you.az.ru/document/d/', 'https://www.microsoft.com.onedrive.file.access.az.ru/login.live.com',
    'http://www.adobe.com.document.cloud.esign.az.ru/public/login', 'https://www.docusign.com.document.to.sign.az.ru/Signing/login',
    'https://www.zoom.us.meeting.invitation.login.az.ru/join/meeting', 'http://www.slack.com.magic.link.for.workspace.az.ru/sso/magic',
    'https://www.spotify.com.family.plan.invitation.az.ru/join/family', 'http://www.bit.ly/login-bank-portal',
    'http://www.tinyurl.com/verify-tax-info', 'http://shorturl.at/dFG12', 'http://is.gd/update_payment_details',
    'http://ow.ly/i/aBcDe', 'http://t.co/phishinglink123', 'https://rebrand.ly/secure-doc-view',
    'http://shorte.st/required-action-account', 'http://adf.ly/12345/important-message', 'https://bit.do/account-verification-step',
    'https://www.amazonsupport.co/gp/css/homepage.html', 'https://www.apple-support-team.org/iforgot/recover',
    'https://www.bankofamerica-secure.net/login/sign-in', 'https://www.chaseonline-jp.com/login/auth',
    'https://www.facebook-helpcenter.io/login/issue', 'https://www.google-mail-services.com/inbox/login',
    'https://www.icloud-findmy.net/auth/login', 'https://www.linkedin-notifications.org/feed/alert',
    'https://www.login-microsoftonline.co/common/login', 'https://www.netflix-billinghelp.com/account/payment',
    'https://www.paypal-resolution-center.info/webscr/home', 'https://www.wellsfargo-onlinebanking.me/signon',
    'https://www.dropbox-files.org/home', 'https://www.dhl-express-tracking.co/track/parcel',
    'https://www.fedex-shipment-docs.com/view/document', 'https://www.ups-package-notifications.net/track',
    'https://www.usps-delivery-issues.org/redelivery/schedule', 'http://login-apple-support-com.gq/manage-account',
    'http://secure-login-wellsfargo-com.tk/auth/login', 'https://signin-google-com-mail-service.ml/accounts',
    'https://www.paypal-com-webapps-mpp-home.cf/login', 'http://verify-bankofamerica-com-secure-site.ga/login-id',
    'https://amazon-com-order-details-gp.io/your-account', 'http://login-microsoft-com-office365.co/auth',
    'http://chase-com-online-banking-services.net/logon', 'https://www.facebook-com-security-checkpoint.xyz/login',
    'http://appleid-com-iforgot-password-reset.info/recover', 'https://netflix-com-account-billing-update.org/user-login',
    'http://dropbox-com-shared-file-access.link/s/doc', 'http://ebay-com-resolution-center-case-details.me/signin',
    'https://instagram-com-help-center-login.top/accounts/password', 'https://twitter-com-account-recovery-flow.biz/begin',
    'http://linkedin-com-profile-security-alert.us/feed', 'http://usps-com-package-redelivery-service.co/schedule',
    'https://www.google-docs-share.com/document/view', 'http://account-live-com-unusual-signin.net/activity',
    'http://support-apple-com-invoice-details.org/receipt/view', 'https://secure-chase-com-verification-required.info/login',
    'http://paypal-com-dispute-resolution.co/activity/dispute', 'http://microsoft-com-secure-login-portal.link/office365',
    'https://www.bankofamerica-com-sign-in.net/login/enter-id', 'http://facebook-com-login-alerts.me/checkpoint',
    'http://amazon-com-account-locked-action.xyz/reactivate', 'https://wellsfargo-com-online-fraud-detection.org/signon',
    'https://www.login-google.com/accounts', 'https://www.secure-apple.com/login', 'https://www.verify-paypal.com/signin',
    'https://www.update-microsoft.com/account', 'http://www.bankofamerica-login.net/', 'http://www.chase-online.org/login',
    'http://181.214.206.55/amazon/update-card/', 'http://103.224.212.222/icloud-login/', 'http://95.216.148.209/wellsfargo/signon/',
    'http://199.192.20.125/google-drive/shared-file.php', 'http://81.95.120.30/paypal/webscr/', 'https://www.facebook.com.login-help.support-page.com/recovery',
    'https://www.amazon-prime.com.special-offer.claim-now.net/account', 'https://www.apple-icloud.com.secure-login-portal.org/auth',
    'https://www.netflix-account.com.billing-update-required.info/user', 'https://www.chase-online.com.security-alert-verification.me/login',
    'https://www.wellsfargo-banking.com.customer-update.xyz/signon', 'https://www.google-services.com.security-notification.link/activity',
    'https://www.bankofamerica-support.com.online-id-verify.top/access', 'https://www.microsoft-office365.com.secure-login-access.biz/signin',
    'https://www.paypal-transactions.com.unauthorized-activity.us/dispute', 'http://www-google-com.drive-share.gq/files/important-doc',
    'http://www-apple-com.find-my-iphone-location.cf/login', 'https://www-facebook-com.profile-security-check.ml/confirm',
    'http://www-amazon-com.order-cancellation-notice.tk/orders', 'https://www-microsoft-com.account-verification.ga/login',
    'http://login-appleid-apple.com-recover-account.co/iforgot', 'http://secure-wellsfargo-online-banking.com-access.io/auth',
    'https://signin-google-com-account-recovery-page.ru/challenge', 'https://paypal-com-webapps-mpp-transaction-review.me/home',
    'http://verify-bankofamerica-com-customer-center.biz/login', 'http://amazon-com-prime-membership-update-required.us/gp/prime',
    'https://login-microsoftonline-com-common-oauth2.info/authorize', 'http://chase-com-jpmorgan-online-services-login.top/logon',
    'http://facebook-com-confirm-identity-page.link/checkpoint/entry', 'http://appleid-apple-com-manage-your-account.xyz/account/manage'
]

# Create test dataset
test_data = []
for url in legitimate_urls:
    test_data.append({'URL': url, 'label': 1})

for url in phishing_urls:
    test_data.append({'URL': url, 'label': 0})

test_df = pd.DataFrame(test_data).sample(frac=1, random_state=42).reset_index(drop=True)
print(f"Test dataset created: {test_df.shape[0]} URLs")
print(f"Test distribution: {Counter(test_df['label'])}")

# =========================
# Feature Engineering
# =========================
print("\n🔧 Extracting features from training dataset...")
X_train_features = process_dataset_with_predefined_features(balanced_df, "Extracting features from training dataset")
y_train = balanced_df['label']

print("\n🔧 Extracting features from test dataset...")
X_test_features = process_dataset_with_predefined_features(test_df, "Extracting features from test dataset")
y_test = test_df['label']

# Ensure both datasets have the same features
common_features = list(set(X_train_features.columns) & set(X_test_features.columns))
X_train_features = X_train_features[common_features]
X_test_features = X_test_features[common_features]

print(f"Training set: {X_train_features.shape[0]} samples with {len(common_features)} features")
print(f"Test set: {X_test_features.shape[0]} samples with {len(common_features)} features")

# Feature scaling
print("\n⚖️ Scaling features...")
scaler = RobustScaler()
X_train_scaled = scaler.fit_transform(X_train_features)
X_test_scaled = scaler.transform(X_test_features)

# Feature selection
print("\n🎯 Selecting best features...")
selector = SelectKBest(score_func=f_classif, k=min(50, X_train_features.shape[1]))
X_train_selected = selector.fit_transform(X_train_scaled, y_train)
X_test_selected = selector.transform(X_test_scaled)

selected_features = selector.get_support(indices=True)
selected_feature_names = [common_features[i] for i in selected_features]

print(f"Selected {X_train_selected.shape[1]} best features")
print("Top 10 selected features:", selected_feature_names[:10])

# =========================
# Model Training
# =========================
print("\n🚀 Training ensemble model...")

# Define optimized models
models = {
    'rf': RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    ),
    'xgb': xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=1,
        random_state=42,
        eval_metric='logloss',
        use_label_encoder=False
    ),
    'lgb': lgb.LGBMClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
        verbosity=-1
    )
}

# Train individual models
trained_models = {}
for name, model in models.items():
    print(f"Training {name}...")
    model.fit(X_train_selected, y_train)
    trained_models[name] = model

# Create and train ensemble
print("Creating ensemble...")
ensemble = VotingClassifier(
    estimators=[(name, model) for name, model in trained_models.items()],
    voting='soft'
)

ensemble.fit(X_train_selected, y_train)

# =========================
# Model Evaluation
# =========================
print("\n" + "="*60)
print("📊 MODEL EVALUATION RESULTS")
print("="*60)

# Make predictions
y_pred = ensemble.predict(X_test_selected)
y_prob = ensemble.predict_proba(X_test_selected)[:, 1]

# Calculate metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print(f"\n🎯 ENSEMBLE PERFORMANCE:")
print(f"   Accuracy:  {accuracy:.3f}")
print(f"   Precision: {precision:.3f}")
print(f"   Recall:    {recall:.3f}")
print(f"   F1-Score:  {f1:.3f}")

print("\n📋 Detailed Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Phishing', 'Legitimate']))

# Feature importance from Random Forest
if 'rf' in trained_models:
    rf_importance = trained_models['rf'].feature_importances_
    feature_importance_df = pd.DataFrame({
        'feature': selected_feature_names,
        'importance': rf_importance
    }).sort_values('importance', ascending=False)
    
    print("\n🏆 Top 10 Most Important Features:")
    for i, (_, row) in enumerate(feature_importance_df.head(10).iterrows()):
        print(f"   {i+1:2d}. {row['feature']:25} ({row['importance']:.4f})")

# Sample predictions
print("\n🔍 Sample Predictions on Test URLs:")
sample_size = min(20, len(test_df))

for idx in range(sample_size):
    url = test_df.iloc[idx]['URL']
    true_label = y_test.iloc[idx]
    pred_label = y_pred[idx]
    pred_prob = y_prob[idx]
    
    label_name = "Legitimate" if pred_label == 1 else "Phishing"
    true_name = "Legitimate" if true_label == 1 else "Phishing"
    status = "✅" if pred_label == true_label else "❌"
    
    print(f"  {status} {url[:70]:70} | True: {true_name:10} | Pred: {label_name:10} | Conf: {pred_prob:.3f}")

# =========================
# Save Model and Components
# =========================
print("\n💾 Saving model and components...")

model_data = {
    'ensemble': ensemble,
    'scaler': scaler,
    'selector': selector,
    'feature_names': common_features,
    'selected_features': selected_features,
    'selected_feature_names': selected_feature_names,
    'feature_extractor': extract_predefined_url_features  # Save the function reference
}

with open('phishing_model_predefined.pkl', 'wb') as f:
    pickle.dump(model_data, f)

print("✅ Model saved as 'phishing_model_predefined.pkl'")
print(f"✅ Training complete! Final accuracy: {accuracy*100:.1f}%")
print("🚀 Ready for integration with HTML frontend and browser extension!")

# =========================
# Create Simple Prediction Function for Testing
# =========================
def predict_url_phishing(url, model_data):
    """
    Simple function to predict if a URL is phishing or legitimate
    """
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
        
        return {
            'prediction': 'Legitimate' if prediction == 1 else 'Phishing',
            'confidence': float(max(probability)),
            'phishing_probability': float(probability[0]),
            'legitimate_probability': float(probability[1])
        }
        
    except Exception as e:
        return {
            'prediction': 'Error',
            'confidence': 0.0,
            'error': str(e)
        }

# Test the prediction function
print("\n🧪 Testing prediction function with sample URLs...")

test_urls = [
    'https://www.google.com',
    'http://secure-banking-update.tk/login.php',
    'https://www.amazon.com/gp/your-account',
    'http://paypal-verify-account.ml/signin'
]

print("\nSample predictions:")
with open('phishing_model_predefined.pkl', 'rb') as f:
    loaded_model_data = pickle.load(f)

for test_url in test_urls:
    result = predict_url_phishing(test_url, loaded_model_data)
    print(f"URL: {test_url}")
    print(f"Prediction: {result['prediction']} (Confidence: {result['confidence']:.3f})")
    print(f"Phishing Prob: {result.get('phishing_probability', 0):.3f}, Legitimate Prob: {result.get('legitimate_probability', 0):.3f}")
    print("-" * 80)
