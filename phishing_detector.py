import json
import urllib.request
import urllib.robotparser
from urllib.parse import urlparse
import re
import requests
from typing import Dict, List, Any
import ssl
import socket
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import certifi

class PhishingDetector:
    def __init__(self, config_file: str = "detector_config.json"):
        self.config = self.load_config(config_file)
        self.suspicious_patterns = self.config.get("suspicious_patterns", [])
        self.whitelist_domains = self.config.get("whitelist_domains", [])
        
    def load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self.create_default_config(config_file)
    
    def create_default_config(self, config_file: str) -> Dict[str, Any]:
        """Create default configuration"""
        default_config = {
            "suspicious_patterns": [
                r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",  # IP addresses
                r"[a-z]+-[a-z]+\.(tk|ml|ga|cf)",     # Suspicious TLDs
                r"secure.*login",
                r"verify.*account"
            ],
            "whitelist_domains": [
                "google.com", "facebook.com", "amazon.com"
            ],
            "ai_model_endpoint": "http://localhost:8000/predict"
        }
        
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        return default_config
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Enhanced URL analysis with SSL and content checking"""
        parsed_url = urlparse(url)
        
        features = {
            "url": url,
            "domain": parsed_url.netloc,
            "has_ip": bool(re.search(r'\d+\.\d+\.\d+\.\d+', parsed_url.netloc)),
            "suspicious_patterns": self.check_suspicious_patterns(url),
            "domain_length": len(parsed_url.netloc),
            "subdomain_count": len(parsed_url.netloc.split('.')) - 2,
            "is_whitelisted": parsed_url.netloc in self.whitelist_domains,
            "ssl_info": self.check_ssl_certificate(parsed_url.netloc),
            "content_analysis": self.analyze_content(url),
            "domain_info": self.get_domain_info(parsed_url.netloc)
        }
        
        ai_score = self.get_ai_prediction(features)
        
        return {
            "features": features,
            "ai_score": ai_score,
            "risk_level": self.calculate_risk_level(features, ai_score)
        }
    
    def check_suspicious_patterns(self, url: str) -> List[str]:
        """Check for suspicious patterns in URL"""
        matches = []
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                matches.append(pattern)
        return matches
    
    def get_ai_prediction(self, features: Dict[str, Any]) -> float:
        """Get AI model prediction (placeholder for actual AI integration)"""
        try:
            # This would call your AI model API
            response = requests.post(
                self.config.get("ai_model_endpoint"),
                json=features,
                timeout=5
            )
            return response.json().get("phishing_probability", 0.0)
        except:
            # Fallback to rule-based scoring
            return self.rule_based_scoring(features)
    
    def rule_based_scoring(self, features: Dict[str, Any]) -> float:
        """Enhanced rule-based scoring"""
        score = 0.0
        
        # URL-based features
        if features["has_ip"]:
            score += 0.3
        if features["suspicious_patterns"]:
            score += 0.2 * len(features["suspicious_patterns"])
        if features["domain_length"] > 30:
            score += 0.1
        if features["subdomain_count"] > 3:
            score += 0.2
        
        # SSL-based features
        ssl_info = features.get("ssl_info", {})
        if not ssl_info.get("valid", False):
            score += 0.3
        if ssl_info.get("is_self_signed", False):
            score += 0.2
        
        # Content-based features
        content = features.get("content_analysis", {})
        if content.get("suspicious_keywords"):
            score += 0.1 * len(content["suspicious_keywords"])
        if content.get("has_password_field", False):
            score += 0.1
        if content.get("external_links_count", 0) > 10:
            score += 0.1
        
        # Domain-based features
        domain_info = features.get("domain_info", {})
        if domain_info.get("is_new_domain", False):
            score += 0.2
        
        # Whitelist override
        if features["is_whitelisted"]:
            score -= 0.5
            
        return min(1.0, max(0.0, score))
    
    def calculate_risk_level(self, features: Dict[str, Any], ai_score: float) -> str:
        """Calculate overall risk level"""
        if features["is_whitelisted"]:
            return "LOW"
        elif ai_score > 0.7:
            return "HIGH"
        elif ai_score > 0.4:
            return "MEDIUM"
        else:
            return "LOW"
    
    def check_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """Check SSL certificate validity"""
        try:
            context = ssl.create_default_context(cafile=certifi.where())
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        "valid": True,
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "subject": dict(x[0] for x in cert['subject']),
                        "expires": cert['notAfter'],
                        "is_self_signed": cert['issuer'] == cert['subject']
                    }
        except Exception as e:
            return {
                "valid": False,
                "error": str(e),
                "is_self_signed": True
            }
    
    def analyze_content(self, url: str) -> Dict[str, Any]:
        """Analyze webpage content for phishing indicators"""
        try:
            response = requests.get(url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract text content
            text_content = soup.get_text().lower()
            
            # Check for suspicious keywords
            suspicious_keywords = [
                'verify account', 'suspended', 'urgent action',
                'click here immediately', 'limited time', 'act now',
                'confirm identity', 'update payment', 'security alert'
            ]
            
            found_keywords = [kw for kw in suspicious_keywords if kw in text_content]
            
            # Check for forms (login/payment forms)
            forms = soup.find_all('form')
            has_password_field = any(
                input_tag.get('type') == 'password' 
                for form in forms 
                for input_tag in form.find_all('input')
            )
            
            # Check for external links
            links = soup.find_all('a', href=True)
            external_links = [
                link['href'] for link in links 
                if link['href'].startswith('http') and 
                urlparse(link['href']).netloc != urlparse(url).netloc
            ]
            
            return {
                "suspicious_keywords": found_keywords,
                "has_forms": len(forms) > 0,
                "has_password_field": has_password_field,
                "form_count": len(forms),
                "external_links_count": len(external_links),
                "title": soup.title.string if soup.title else "",
                "has_favicon": bool(soup.find('link', rel='icon'))
            }
            
        except Exception as e:
            return {"error": str(e), "analyzed": False}
    
    def get_domain_info(self, domain: str) -> Dict[str, Any]:
        """Get domain registration information"""
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            days_old = (datetime.now() - creation_date).days if creation_date else 0
            
            return {
                "creation_date": str(creation_date) if creation_date else None,
                "days_old": days_old,
                "registrar": w.registrar,
                "is_new_domain": days_old < 30 if creation_date else True
            }
        except Exception as e:
            return {"error": str(e), "is_new_domain": True}
