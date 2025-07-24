#!/usr/bin/env python3
import json
from phishing_detector import PhishingDetector

def main():
    detector = PhishingDetector()
    
    # Test URLs
    test_urls = [
        "https://secure-login-amazon.tk/verify",
        "https://192.168.1.1/login",
        "https://google.com",
        "https://paypal-security-update.ml/account"
    ]
    
    results = []
    for url in test_urls:
        result = detector.analyze_url(url)
        results.append(result)
        
        print(f"\nURL: {url}")
        print(f"Risk Level: {result['risk_level']}")
        print(f"AI Score: {result['ai_score']:.2f}")
        print(f"Suspicious Patterns: {result['features']['suspicious_patterns']}")
    
    # Save results to JSON
    with open('detection_results.json', 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()