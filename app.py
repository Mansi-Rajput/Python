# app.py - Flask web application for phishing detection
from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
import re
import ssl
import socket
import whois
from urllib.parse import urlparse
import datetime
import tldextract
import threading
import time

app = Flask(__name__)

class PhishingDetector:
    def __init__(self, url):
        self.url = url
        self.domain = urlparse(url).netloc
        self.extracted = tldextract.extract(url)
        self.full_domain = f"{self.extracted.domain}.{self.extracted.suffix}"
        self.features = {}
        self.score = 0
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
   
    def fetch_page(self):
        """Fetch the page content and return soup object"""
        try:
            response = requests.get(self.url, headers=self.headers, timeout=10, verify=False)
            self.page_content = response.text
            self.soup = BeautifulSoup(self.page_content, 'html.parser')
            return True
        except Exception as e:
            print(f"Error fetching the page: {e}")
            return False
    
    def check_ssl(self):
        """Check SSL certificate validity"""
        try:
            parsed_url = urlparse(self.url)
            hostname = parsed_url.netloc
            
            # Extract port if specified, otherwise use default 443 for HTTPS
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            if parsed_url.scheme != 'https':
                self.features['has_ssl'] = False
                return
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
            # Check certificate expiration
            not_after = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            not_before = datetime.datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
            
            current_time = datetime.datetime.utcnow()
            is_valid = not_before <= current_time <= not_after
            
            # Check if certificate is issued to the right domain
            subject_alt_names = []
            for type_name, alt_name in cert.get('subjectAltName', []):
                if type_name == 'DNS':
                    subject_alt_names.append(alt_name)
            
            domain_match = False
            for name in subject_alt_names:
                if name == hostname or (name.startswith('*.') and hostname.endswith(name[1:])):
                    domain_match = True
                    break
                    
            self.features['has_ssl'] = is_valid and domain_match
        except Exception as e:
            print(f"SSL verification error: {e}")
            self.features['has_ssl'] = False
    
    def check_domain_age(self):
        """Check domain registration age"""
        try:
            w = whois.whois(self.full_domain)
            
            # Handle different date formats
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                domain_age = (datetime.datetime.now() - creation_date).days
                self.features['domain_age'] = domain_age
            else:
                self.features['domain_age'] = None
        except Exception as e:
            print(f"Error checking domain age: {e}")
            self.features['domain_age'] = None
    
    def check_form_elements(self):
        """Check for login form elements"""
        try:
            forms = self.soup.find_all('form')
            self.features['has_login_form'] = False
            self.features['password_fields'] = 0
            self.features['suspicious_form_attrs'] = []
            
            for form in forms:
                # Look for password fields
                password_fields = form.find_all('input', {'type': 'password'})
                if password_fields:
                    self.features['has_login_form'] = True
                    self.features['password_fields'] += len(password_fields)
                
                # Check for suspicious form attributes
                if form.get('action') and (form['action'] == '' or form['action'] == '#' or form['action'].startswith('http') and self.domain not in form['action']):
                    self.features['suspicious_form_attrs'].append('suspicious_action')
                
                # Check for external form submissions
                if form.get('action') and urlparse(form['action']).netloc and urlparse(form['action']).netloc != self.domain:
                    self.features['suspicious_form_attrs'].append('external_submission')
        except Exception as e:
            print(f"Error checking form elements: {e}")
    
    def check_brand_impersonation(self):
        """Check for brand names in the content"""
        try:
            common_brands = [
                'paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook', 
                'instagram', 'netflix', 'bank', 'chase', 'wellsfargo', 'citibank',
                'amex', 'mastercard', 'visa', 'account', 'login', 'signin', 'verify'
            ]
            
            text_content = self.soup.get_text().lower()
            title = self.soup.title.string.lower() if self.soup.title else ""
            
            self.features['brand_mentions'] = []
            self.features['brand_in_domain'] = False
            
            # Check for brands in page content
            for brand in common_brands:
                if brand in text_content or brand in title:
                    self.features['brand_mentions'].append(brand)
            
            # Check if brand is in domain but doesn't match official domain
            domain_lower = self.full_domain.lower()
            for brand in common_brands:
                if brand in domain_lower:
                    self.features['brand_in_domain'] = True
        except Exception as e:
            print(f"Error checking brand impersonation: {e}")
    
    def check_redirect_behavior(self):
        """Check for suspicious redirects in JavaScript"""
        try:
            scripts = self.soup.find_all('script')
            self.features['suspicious_redirects'] = []
            
            redirect_patterns = [
                r'window\.location\s*=',
                r'location\.href\s*=',
                r'document\.location\s*=',
                r'location\.assign\(',
                r'location\.replace\(',
                r'document\.location\.href\s*='
            ]
            
            for script in scripts:
                if script.string:
                    for pattern in redirect_patterns:
                        matches = re.findall(pattern, script.string)
                        if matches:
                            self.features['suspicious_redirects'].extend(matches)
        except Exception as e:
            print(f"Error checking redirect behavior: {e}")
    
    def check_obfuscation(self):
        """Check for obfuscated JavaScript"""
        try:
            scripts = self.soup.find_all('script')
            self.features['obfuscation_detected'] = False
            
            obfuscation_indicators = [
                r'eval\(',
                r'unescape\(',
                r'document\.write\(',
                r'fromCharCode',
                r'\\x[0-9a-f]{2}',
                r'\\u[0-9a-f]{4}'
            ]
            
            for script in scripts:
                if script.string:
                    for indicator in obfuscation_indicators:
                        if re.search(indicator, script.string):
                            self.features['obfuscation_detected'] = True
                            break
        except Exception as e:
            print(f"Error checking JS obfuscation: {e}")
    
    def check_security_indicators(self):
        """Check for security indicators like favicon, protocol, etc."""
        try:
            # Check if favicon exists
            favicon = self.soup.find('link', rel=lambda x: x and ('icon' in x.lower() or 'shortcut icon' in x.lower()))
            self.features['has_favicon'] = favicon is not None
            
            # Check for HTTP protocol
            self.features['is_https'] = self.url.startswith('https://')
            
            # Check for suspicious URL characteristics
            self.features['has_suspicious_url'] = False
            suspicious_indicators = [
                '@', 'localhost', '127.0.0.1', '.tk', '.ml', '.ga', '.cf', '.gq',
                '-secure', '-login', '-signin', '-verify', 'account-update'
            ]
            
            for indicator in suspicious_indicators:
                if indicator in self.url.lower():
                    self.features['has_suspicious_url'] = True
                    break
        except Exception as e:
            print(f"Error checking security indicators: {e}")
    
    def calculate_phishing_score(self):
        """Calculate a phishing probability score (0-100) based on features"""
        try:
            # Initialize base score
            score = 0
            total_weight = 0
            
            # SSL Certificate
            weight = 20
            total_weight += weight
            if not self.features.get('has_ssl', False):
                score += weight
            
            # Domain Age
            weight = 15 
            total_weight += weight
            domain_age = self.features.get('domain_age')
            if domain_age is not None and domain_age < 30:  # Domain less than 30 days old
                score += weight
            
            # Form Elements
            weight = 15 
            total_weight += weight
            if self.features.get('has_login_form', False) and self.features.get('suspicious_form_attrs', []):
                score += weight
            
            # Brand Impersonation
            weight = 15
            total_weight += weight
            if self.features.get('brand_in_domain', False) and self.features.get('brand_mentions', []):
                score += weight
            
            # Redirects
            weight = 10
            total_weight += weight
            if self.features.get('suspicious_redirects', []):
                score += weight
            
            # Obfuscation
            weight = 10
            total_weight += weight
            if self.features.get('obfuscation_detected', False):
                score += weight
            
            # Security Indicators
            weight = 15 
            total_weight += weight
            if self.features.get('has_suspicious_url', False) or not self.features.get('is_https', True):
                score += weight

            # Calculate percentage
            self.score = int((score / total_weight) * 100)
            
            return self.score
        except Exception as e:
            print(f"Error calculating phishing score: {e}")
            return 50  # Return a neutral score on error
    
    def analyze(self):
        """Run the complete analysis and return the results"""
        if not self.fetch_page():
            return {"error": "Failed to fetch page"}
        
        self.check_ssl()
        self.check_domain_age()
        self.check_form_elements()
        self.check_brand_impersonation()
        self.check_redirect_behavior()
        self.check_obfuscation()
        self.check_security_indicators()
        self.calculate_phishing_score()
        
        risk_level = "High" if self.score > 70 else "Medium" if self.score > 40 else "Low"
        
        results = {
            "url": self.url,
            "domain": self.domain,
            "score": self.score,
            "risk_level": risk_level,
            "features": {
                "ssl": {
                    "has_valid_ssl": self.features.get('has_ssl', False),
                    "is_https": self.features.get('is_https', False)
                },
                "domain_age": self.features.get('domain_age'),
                "login_form": {
                    "detected": self.features.get('has_login_form', False),
                    "password_fields": self.features.get('password_fields', 0),
                    "suspicious_attrs": self.features.get('suspicious_form_attrs', [])
                },
                "brand_impersonation": {
                    "brand_mentions": self.features.get('brand_mentions', []),
                    "brand_in_domain": self.features.get('brand_in_domain', False)
                },
                "suspicious_redirects": bool(self.features.get('suspicious_redirects', [])),
                "obfuscation_detected": self.features.get('obfuscation_detected', False),
                "has_suspicious_url": self.features.get('has_suspicious_url', False),
                "has_favicon": self.features.get('has_favicon', False)
            }
        }
        
        return results

# Store the scan history and results
scan_history = {}

# Function to run analysis in a background thread
def analyze_url_task(scan_id, url):
    try:
        detector = PhishingDetector(url)
        results = detector.analyze()
        scan_history[scan_id] = {
            "status": "completed",
            "results": results,
            "timestamp": datetime.datetime.now().isoformat()
        }
    except Exception as e:
        scan_history[scan_id] = {
            "status": "failed",
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    # Basic URL validation
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Generate a unique scan ID
    scan_id = str(int(time.time()))
    
    # Initialize the scan in history
    scan_history[scan_id] = {
        "status": "processing",
        "url": url,
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    # Start analysis in a background thread
    threading.Thread(target=analyze_url_task, args=(scan_id, url)).start()
    
    return jsonify({"scan_id": scan_id, "status": "processing"})

@app.route('/api/results/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    if scan_id not in scan_history:
        return jsonify({"error": "Scan ID not found"}), 404
    
    return jsonify(scan_history[scan_id])

@app.route('/api/history', methods=['GET'])
def get_scan_history():
    # Return a list of recent scans (last 10)
    recent_scans = []
    for scan_id, scan_data in sorted(scan_history.items(), key=lambda x: x[1]['timestamp'], reverse=True)[:10]:
        scan_info = {
            "scan_id": scan_id,
            "url": scan_data.get("url", ""),
            "status": scan_data.get("status", ""),
            "timestamp": scan_data.get("timestamp", ""),
        }
        
        if scan_data.get("status") == "completed" and "results" in scan_data:
            scan_info["score"] = scan_data["results"].get("score", 0)
            scan_info["risk_level"] = scan_data["results"].get("risk_level", "Unknown")
        
        recent_scans.append(scan_info)
    
    return jsonify({"history": recent_scans})

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)