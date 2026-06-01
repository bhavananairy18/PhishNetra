from flask import Flask, request, jsonify
from flask_cors import CORS
# import cv2
# import numpy as np
# import tensorflow as tf

app = Flask(__name__)
CORS(app) # Allow cross-origin requests from the Chrome Extension

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "running"}), 200

@app.route('/api/analyze_visual', methods=['POST'])
def analyze_visual_similarity():
    """
    Endpoint to receive a screenshot or image from the extension
    and compare it visually against known trusted sites to detect
    spoofing (e.g. fake Google login page).
    """
    data = request.json
    
    if not data or 'image_b64' not in data:
        return jsonify({"error": "Missing image_b64 payload"}), 400
        
    url = data.get('url', 'unknown')
    image_b64 = data['image_b64']
    
    # ---------------------------------------------
    # TODO: Implement Advanced Computer Vision here
    # ---------------------------------------------
    # 1. Decode base64 image 
    # 2. Extract features (e.g., OpenCV ORB/SIFT or CNN feature extractor)
    # 3. Compare with database of known trusted brands' UI templates
    # 4. If visual similarity is HIGH (>90%) but URL domain is WRONG => Return High Risk!
    
    # Mock Response
    mock_score = 0
    mock_status = "Safe"
    mock_reasons = []
    
    # Example logic:
    # if model.predict(image) == "Google Login" and "google.com" not in url:
    #     mock_score = 90
    #     mock_status = "Dangerous"
    #     mock_reasons.append("Visual layout matches Google, but URL is incorrect.")
    
    return jsonify({
        "url": url,
        "visual_risk_score": mock_score,
        "status": mock_status,
        "reasons": mock_reasons
    }), 200

if __name__ == '__main__':
    # Run the server on port 5000
    app.run(host='0.0.0.0', port=5000, debug=True)
