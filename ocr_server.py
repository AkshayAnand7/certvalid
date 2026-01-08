"""
PaddleOCR Flask Server
Provides OCR API endpoint for certificate text extraction
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from paddleocr import PaddleOCR
import base64
import tempfile
import os
import re

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend access

# Initialize PaddleOCR with English model
# use_angle_cls=True enables text angle classification
# use_gpu=False for CPU-only environments
print("Initializing PaddleOCR... (this may take a moment on first run)")
ocr = PaddleOCR(
    use_angle_cls=True,
    lang='en',
    use_gpu=False,
    show_log=False
)
print("PaddleOCR initialized successfully!")


def extract_field(lines, keywords):
    """
    Extract a field value from OCR text lines based on keywords.
    Looks for lines containing any of the keywords and extracts the value.
    """
    for line in lines:
        line_lower = line.lower()
        for keyword in keywords:
            if keyword in line_lower:
                # Try to extract value after colon or the rest of the line
                if ':' in line:
                    return line.split(':', 1)[1].strip()
                # Remove the keyword and return the rest
                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                result = pattern.sub('', line).strip()
                if result:
                    return result
    return ""


def parse_certificate_fields(text_lines):
    """
    Parse OCR text lines to extract certificate fields using heuristics.
    """
    # Filter out very short lines (noise)
    lines = [line.strip() for line in text_lines if len(line.strip()) > 2]
    
    # Extract fields using keyword matching
    name = extract_field(lines, ['name', 'student', 'awarded to', 'certify that', 'this is to certify'])
    register_number = extract_field(lines, ['register', 'reg no', 'registration', 'id number', 'enrollment', 'roll no'])
    institution = extract_field(lines, ['university', 'college', 'institute', 'institution', 'school'])
    degree = extract_field(lines, ['degree', 'bachelor', 'master', 'diploma', 'certificate', 'programme', 'course'])
    year = extract_field(lines, ['year', 'dated', 'date'])
    
    # If name not found by keyword, try to find a capitalized name pattern
    if not name:
        for line in lines:
            # Look for lines that appear to be names (mostly capital letters, 2-4 words)
            words = line.split()
            if 2 <= len(words) <= 4 and all(word[0].isupper() for word in words if word):
                # Check if it's not a common header
                lower = line.lower()
                if not any(skip in lower for skip in ['certificate', 'university', 'college', 'degree']):
                    name = line
                    break
    
    return {
        "name": name,
        "registerNumber": register_number,
        "institution": institution,
        "degree": degree,
        "year": year,
        "gpa": ""
    }


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "ok", "service": "PaddleOCR"})


@app.route('/ocr', methods=['POST'])
def extract_text():
    """
    OCR endpoint - accepts base64 encoded image and returns extracted certificate fields
    
    Request body:
    {
        "image": "data:image/png;base64,..."
    }
    
    Response:
    {
        "name": "...",
        "registerNumber": "...",
        "institution": "...",
        "degree": "...",
        "year": "...",
        "gpa": "",
        "rawText": ["line1", "line2", ...]
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'image' not in data:
            return jsonify({"error": "No image provided"}), 400
        
        image_data = data['image']
        
        # Remove data URL prefix if present
        if ',' in image_data:
            image_data = image_data.split(',')[1]
        
        # Decode base64 to bytes
        image_bytes = base64.b64decode(image_data)
        
        # Save to temporary file (PaddleOCR needs file path)
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp_file:
            tmp_file.write(image_bytes)
            tmp_path = tmp_file.name
        
        try:
            # Run OCR
            result = ocr.ocr(tmp_path, cls=True)
            
            # Extract text from results
            text_lines = []
            if result and result[0]:
                for line in result[0]:
                    if line and len(line) > 1:
                        text = line[1][0]  # Get the text content
                        text_lines.append(text)
            
            # Parse certificate fields
            fields = parse_certificate_fields(text_lines)
            fields['rawText'] = text_lines
            
            return jsonify(fields)
            
        finally:
            # Clean up temp file
            os.unlink(tmp_path)
            
    except Exception as e:
        print(f"OCR Error: {str(e)}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print("\n" + "="*50)
    print("PaddleOCR Server Starting...")
    print("API Endpoint: http://localhost:5000/ocr")
    print("Health Check: http://localhost:5000/health")
    print("="*50 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
