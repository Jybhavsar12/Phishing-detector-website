from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from phishing_detector import PhishingDetector
import uvicorn

app = FastAPI(title="Phishing Detector API", version="1.0.0")

# Initialize detector
detector = PhishingDetector()

class URLRequest(BaseModel):
    url: str

class DetectionResponse(BaseModel):
    url: str
    risk_level: str
    ai_score: float
    features: dict
    recommendations: list

@app.post("/analyze", response_model=DetectionResponse)
async def analyze_url(request: URLRequest):
    """Analyze a URL for phishing indicators"""
    try:
        result = detector.analyze_url(request.url)
        
        # Generate recommendations
        recommendations = generate_recommendations(result)
        
        return DetectionResponse(
            url=request.url,
            risk_level=result["risk_level"],
            ai_score=result["ai_score"],
            features=result["features"],
            recommendations=recommendations
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "phishing-detector"}

@app.get("/", response_class=HTMLResponse)
async def get_web_interface():
    """Serve the web interface"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Phishing Detector</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .container { background: #f5f5f5; padding: 20px; border-radius: 8px; }
            .result { margin-top: 20px; padding: 15px; border-radius: 5px; }
            .high-risk { background-color: #ffebee; border-left: 4px solid #f44336; }
            .medium-risk { background-color: #fff3e0; border-left: 4px solid #ff9800; }
            .low-risk { background-color: #e8f5e8; border-left: 4px solid #4caf50; }
            input[type="url"] { width: 70%; padding: 10px; margin-right: 10px; }
            button { padding: 10px 20px; background: #2196f3; color: white; border: none; cursor: pointer; }
            .loading { display: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Phishing Site Detector</h1>
            <p>Enter a URL to analyze for phishing indicators:</p>
            
            <div>
                <input type="url" id="urlInput" placeholder="https://example.com" />
                <button onclick="analyzeURL()">Analyze</button>
            </div>
            
            <div id="loading" class="loading">Analyzing...</div>
            <div id="result"></div>
        </div>

        <script>
            async function analyzeURL() {
                const url = document.getElementById('urlInput').value;
                const loading = document.getElementById('loading');
                const result = document.getElementById('result');
                
                if (!url) {
                    alert('Please enter a URL');
                    return;
                }
                
                loading.style.display = 'block';
                result.innerHTML = '';
                
                try {
                    const response = await fetch('/analyze', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: url })
                    });
                    
                    const data = await response.json();
                    displayResult(data);
                } catch (error) {
                    result.innerHTML = '<div class="result high-risk">Error: ' + error.message + '</div>';
                } finally {
                    loading.style.display = 'none';
                }
            }
            
            function displayResult(data) {
                const riskClass = data.risk_level.toLowerCase() + '-risk';
                const result = document.getElementById('result');
                
                result.innerHTML = `
                    <div class="result ${riskClass}">
                        <h3>Analysis Result</h3>
                        <p><strong>URL:</strong> ${data.url}</p>
                        <p><strong>Risk Level:</strong> ${data.risk_level}</p>
                        <p><strong>AI Score:</strong> ${data.ai_score.toFixed(2)}</p>
                        
                        <h4>Recommendations:</h4>
                        <ul>
                            ${data.recommendations.map(rec => '<li>' + rec + '</li>').join('')}
                        </ul>
                        
                        <details>
                            <summary>Technical Details</summary>
                            <pre>${JSON.stringify(data.features, null, 2)}</pre>
                        </details>
                    </div>
                `;
            }
        </script>
    </body>
    </html>
    """

def generate_recommendations(result):
    """Generate security recommendations based on analysis"""
    recommendations = []
    features = result["features"]
    risk_level = result["risk_level"]
    
    if risk_level == "HIGH":
        recommendations.append("⚠️ HIGH RISK: Do not enter personal information on this site")
        recommendations.append("🚫 Avoid clicking links or downloading files")
        recommendations.append("📞 Contact the legitimate organization directly if needed")
    
    if features.get("has_ip"):
        recommendations.append("🔍 Site uses IP address instead of domain name - suspicious")
    
    ssl_info = features.get("ssl_info", {})
    if not ssl_info.get("valid"):
        recommendations.append("🔒 No valid SSL certificate - data transmission not secure")
    
    content = features.get("content_analysis", {})
    if content.get("suspicious_keywords"):
        recommendations.append("⚡ Contains urgent/suspicious language - be cautious")
    
    domain_info = features.get("domain_info", {})
    if domain_info.get("is_new_domain"):
        recommendations.append("📅 Domain is very new - exercise extra caution")
    
    if risk_level == "LOW":
        recommendations.append("✅ Site appears legitimate, but always verify URLs carefully")
    
    return recommendations

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)