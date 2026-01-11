"""
PaddleOCR Backend Service for CertValid
Extracts text from certificate images/PDFs using PaddleOCR
"""

import os
import re
import base64
import io
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
from paddleocr import PaddleOCR

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, origins=["*"])  # Update for production

# Initialize PaddleOCR (English, angle classification enabled)
ocr = PaddleOCR(use_angle_cls=True, lang='en', show_log=False)

# Max file size: 10MB
MAX_FILE_SIZE = 10 * 1024 * 1024


def decode_base64_image(base64_string: str) -> Image.Image:
    """Decode base64 string to PIL Image"""
    # Remove data URL prefix if present
    if ',' in base64_string:
        base64_string = base64_string.split(',')[1]
    
    image_data = base64.b64decode(base64_string)
    return Image.open(io.BytesIO(image_data))


def pdf_to_images(pdf_data: bytes) -> list:
    """Convert PDF bytes to list of PIL Images"""
    try:
        from pdf2image import convert_from_bytes
        images = convert_from_bytes(pdf_data, dpi=200)
        return images
    except Exception as e:
        logger.error(f"PDF conversion failed: {e}")
        raise ValueError(f"PDF conversion failed: {e}")


def extract_text_from_image(image: Image.Image) -> str:
    """Run PaddleOCR on image and return extracted text"""
    import numpy as np
    
    # Convert to RGB if necessary
    if image.mode != 'RGB':
        image = image.convert('RGB')
    
    # Resize if image is too large (PaddleOCR may struggle with very large images)
    max_dimension = 2000
    if max(image.size) > max_dimension:
        ratio = max_dimension / max(image.size)
        new_size = (int(image.size[0] * ratio), int(image.size[1] * ratio))
        image = image.resize(new_size, Image.LANCZOS)
    
    # Convert PIL Image to numpy array (what PaddleOCR actually expects)
    img_array = np.array(image)
    
    # Run OCR with numpy array
    result = ocr.ocr(img_array, cls=True)
    
    # Extract text from result
    lines = []
    if result and result[0]:
        for line in result[0]:
            if len(line) >= 2 and line[1]:
                text = line[1][0]  # Get the text content
                lines.append(text)
    
    return '\n'.join(lines)


def parse_certificate_fields(raw_text: str) -> dict:
    """Parse OCR text to extract certificate fields with improved heuristics"""
    import sys
    lines = [l.strip() for l in raw_text.split('\n') if l.strip()]
    full_text = ' '.join(lines)  # For multi-line pattern matching
    
    # Use print with flush for debugging (goes to docker logs)
    print(f"=== RAW OCR TEXT ===", flush=True)
    print(raw_text, flush=True)
    print(f"=== PARSED LINES ===", flush=True)
    for i, line in enumerate(lines):
        print(f"  [{i}]: {line}", flush=True)
    
    # Initialize results
    name = ""
    reg = ""
    institution = ""
    degree = ""
    year = ""
    gpa = ""
    
    # =================================
    # NAME EXTRACTION
    # =================================
    # Pattern 1: "certify that Mr./Ms. NAME"
    name_match = re.search(
        r'(?:certif(?:y|ies|ied)\s+that|awarded\s+to|presented\s+to|granted\s+to)\s*'
        r'(?:mr\.?|ms\.?|mrs\.?|miss\.?|shri\.?|smt\.?)?\s*'
        r'([A-Z][A-Za-z\s\.]+?)(?=\s*(?:has|of|from|,|bearing|with|for|register|roll|\d|$))',
        full_text, re.IGNORECASE
    )
    if name_match:
        name = name_match.group(1).strip()
        # Clean up trailing common words
        name = re.sub(r'\s+(has|of|from|bearing|with|for)$', '', name, flags=re.IGNORECASE).strip()
    
    # Pattern 2: Look for "Name:" label
    if not name:
        for line in lines:
            if 'name' in line.lower() and ':' in line:
                parts = line.split(':', 1)
                if len(parts) > 1 and parts[1].strip():
                    name = parts[1].strip()
                    break
    
    # Pattern 3: Look for standalone name after "This is to certify" type line
    if not name:
        for i, line in enumerate(lines):
            if any(kw in line.lower() for kw in ['certify', 'awarded', 'presented', 'granted']):
                # Check next few lines for a name
                for j in range(i+1, min(i+4, len(lines))):
                    candidate = lines[j].strip()
                    # Skip lines that look like institutions or have keywords
                    if re.match(r'^[A-Z][a-z]+\s+[A-Z][a-z]+', candidate) and \
                       not any(kw in candidate.lower() for kw in ['college', 'university', 'institute', 'school', 'degree', 'bachelor', 'master']):
                        name = candidate
                        break
                break
    
    # =================================
    # INSTITUTION EXTRACTION (College/University name with Dr./Prof. prefix)
    # =================================
    # First look for "Dr." or similar prefixed institution names
    for line in lines:
        if re.match(r'^(?:dr\.?|prof\.?)\s*[a-z]', line, re.IGNORECASE):
            if any(kw in line.lower() for kw in ['institute', 'college', 'university', 'polytechnic']):
                institution = line
                break
    
    # If not found, look for lines containing institution keywords
    if not institution:
        for line in lines:
            lower = line.lower()
            if any(kw in lower for kw in ['institute of technology', 'engineering college', 'arts and science', 'polytechnic']):
                if name and name.lower() in lower:
                    continue
                institution = line
                break
    
    # =================================
    # ORGANIZER EXTRACTION (Event organizer like "Centre for IoT")
    # =================================
    organizer = ""
    for line in lines:
        lower = line.lower()
        # Look for organizer keywords
        if any(kw in lower for kw in ['centre for', 'center for', 'organized by', 'organised by', 'conducted by', 'department of']):
            organizer = line
            break
        # Also check for patterns like "C-IoT" or "MIT"
        if 'iot' in lower or 'mit' in lower or 'iit' in lower or 'nit' in lower:
            if not organizer and len(line) > 5:
                organizer = line
    
    # =================================
    # REGISTER NUMBER EXTRACTION
    # =================================
    for line in lines:
        lower = line.lower()
        if any(kw in lower for kw in ['register', 'reg no', 'roll no', 'enrollment', 'student id', 'id number', 'registration']):
            if ':' in line:
                value = line.split(':', 1)[1].strip()
                if value and not reg:
                    reg = value
            else:
                match = re.search(r'[A-Z0-9]{2,}\d{4,}', line.upper())
                if match and not reg:
                    reg = match.group()
    
    # Fallback: Look for alphanumeric pattern anywhere
    if not reg:
        for line in lines:
            match = re.search(r'\b[A-Z]{1,4}\d{6,}\b', line.upper())
            if match:
                reg = match.group()
                break
    
    # =================================
    # DEGREE EXTRACTION
    # =================================
    degree_patterns = [
        r'\b(bachelor\s+of\s+[\w\s]+)',
        r'\b(master\s+of\s+[\w\s]+)',
        r'\b(b\.?\s*(?:sc|tech|e|a|com|ca)\.?(?:\s+[\w\s]+)?)',
        r'\b(m\.?\s*(?:sc|tech|e|a|com|ca|ba|phil)\.?(?:\s+[\w\s]+)?)',
        r'\b(diploma\s+in\s+[\w\s]+)',
        r'\b(ph\.?d\.?(?:\s+in\s+[\w\s]+)?)',
    ]
    for line in lines:
        for pattern in degree_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match and not degree:
                degree = match.group(1).strip()
                break
        if degree:
            break
    
    # Fallback: line containing degree keywords
    if not degree:
        for line in lines:
            if any(kw in line.lower() for kw in ['bachelor', 'master', 'diploma', 'b.tech', 'm.tech', 'b.sc', 'm.sc', 'b.e', 'm.e']):
                degree = line
                break
    
    # =================================
    # YEAR EXTRACTION
    # =================================
    year_match = re.search(r'\b(20\d{2})\b', full_text)
    if year_match:
        year = year_match.group(1)
    
    # =================================
    # GPA EXTRACTION
    # =================================
    for line in lines:
        if any(kw in line.lower() for kw in ['gpa', 'cgpa', 'grade', 'percentage', 'marks']):
            gpa_match = re.search(r'(\d+\.?\d*)\s*(?:%|/|cgpa|gpa)?', line, re.IGNORECASE)
            if gpa_match:
                gpa = gpa_match.group(1)
                break
    
    # Default year
    if not year:
        from datetime import datetime as dt
        year = str(dt.now().year)
    
    result = {
        'name': name,
        'registerNumber': reg,
        'institution': institution,
        'organizer': organizer,
        'degree': degree,
        'year': year,
        'gpa': gpa,
        'rawText': raw_text
    }
    
    print(f"=== PARSED RESULT ===")
    print(f"name={name}, reg={reg}, institution={institution}, organizer={organizer}, degree={degree}")
    
    return result


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'ocr-service'})


@app.route('/ocr', methods=['POST'])
def process_ocr():
    """
    OCR endpoint - accepts base64 image/PDF or multipart file upload
    
    JSON body: {"image": "data:image/png;base64,..."}
    or multipart: file field named "certificate_pdf" or "file"
    """
    try:
        raw_text = ""
        
        # Check for JSON body with base64 image
        if request.is_json:
            data = request.get_json()
            image_data = data.get('image', '')
            
            if not image_data:
                return jsonify({'error': 'No image data provided'}), 400
            
            # Check if it's a PDF (base64)
            if 'application/pdf' in image_data or image_data.startswith('JVBER'):
                # Decode PDF
                if ',' in image_data:
                    pdf_b64 = image_data.split(',')[1]
                else:
                    pdf_b64 = image_data
                pdf_bytes = base64.b64decode(pdf_b64)
                
                # Convert PDF pages to images and OCR each
                images = pdf_to_images(pdf_bytes)
                all_text = []
                for img in images:
                    text = extract_text_from_image(img)
                    all_text.append(text)
                raw_text = '\n'.join(all_text)
            else:
                # Regular image
                image = decode_base64_image(image_data)
                raw_text = extract_text_from_image(image)
        
        # Check for multipart file upload
        elif 'certificate_pdf' in request.files or 'file' in request.files:
            file = request.files.get('certificate_pdf') or request.files.get('file')
            
            if file.content_length and file.content_length > MAX_FILE_SIZE:
                return jsonify({'error': 'File too large. Max 10MB allowed.'}), 400
            
            file_data = file.read()
            
            # Check file type
            if file.filename.lower().endswith('.pdf'):
                images = pdf_to_images(file_data)
                all_text = []
                for img in images:
                    text = extract_text_from_image(img)
                    all_text.append(text)
                raw_text = '\n'.join(all_text)
            else:
                # Assume image
                image = Image.open(io.BytesIO(file_data))
                raw_text = extract_text_from_image(image)
        else:
            return jsonify({'error': 'No file or image data provided'}), 400
        
        # Parse fields from extracted text
        result = parse_certificate_fields(raw_text)
        
        logger.info(f"OCR completed. Extracted: name={result['name']}, degree={result['degree']}")
        
        return jsonify(result)
    
    except Exception as e:
        logger.exception("OCR processing failed")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
