# 🛡️ Phishing Site Detector

A comprehensive phishing detection system that analyzes URLs for malicious indicators using both rule-based analysis and AI-powered detection.

## Features

- **Multi-layered Analysis**: Combines URL patterns, SSL certificates, content analysis, and domain information
- **Web Interface**: User-friendly web UI for real-time URL analysis
- **REST API**: FastAPI-based API for programmatic access
- **AI Integration**: Ready for machine learning model integration
- **Comprehensive Reporting**: Detailed analysis with security recommendations

## Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### Run Web Interface

```bash
python web_interface.py
```

Visit `http://localhost:8000` to access the web interface.

### Command Line Usage

```bash
python main.py
```

## API Endpoints

- `POST /analyze` - Analyze a URL for phishing indicators
- `GET /health` - Health check endpoint
- `GET /` - Web interface

### Example API Usage

```bash
curl -X POST "http://localhost:8000/analyze" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'
```

## Detection Features

- **URL Analysis**: IP addresses, suspicious TLDs, domain patterns
- **SSL Certificate Validation**: Certificate validity and issuer verification
- **Content Analysis**: Suspicious keywords, forms, external links
- **Domain Intelligence**: Registration date, registrar information
- **Whitelist Support**: Trusted domain bypass

## Configuration

Edit `detector_config.json` to customize:
- Suspicious patterns
- Whitelisted domains
- AI model endpoints
- Risk thresholds

## Requirements

- Python 3.7+
- FastAPI
- BeautifulSoup4
- Requests
- python-whois

# Phishing-detector-website
