const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS and JSON parsing
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve static frontend files from public/ or current directory
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

// Explicit route for root index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Configure Multer for in-memory file uploads (max 10MB)
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/jpg', 'application/pdf'];
        if (allowedTypes.includes(file.mimetype) || file.originalname.match(/\.(jpg|jpeg|png|webp|pdf)$/i)) {
            cb(null, true);
        } else {
            cb(new Error('Unsupported file format. Please upload JPG, PNG, WebP, or PDF.'));
        }
    }
});

/**
 * Robust Gemini extraction helper
 * Uses @google/genai or @google/generative-ai
 */
async function callGeminiVision(buffer, mimeType) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey || apiKey === 'YOUR_GEMINI_API_KEY' || apiKey.trim() === '') {
        throw new Error('GEMINI_API_KEY is not configured in .env file.');
    }

    const base64Data = buffer.toString('base64');

    const promptText = `You are a certificate information extraction system.

Analyze the uploaded certificate carefully.

Extract only information that is visibly present in the certificate.

Return ONLY valid JSON using this exact structure:

{
  "name": "",
  "certificateId": "",
  "registerNumber": "",
  "institution": "",
  "organizer": "",
  "course": "",
  "date": ""
}

Rules:

1. Do not guess missing information. If a field cannot be identified, return an empty string.
2. Do not invent values.
3. "name": Extract the full name of the recipient/student receiving the certificate (e.g. "INDIRAJITH T.B", "AKSHAY ANAND M P").
4. "institution": Extract the student's affiliated college/university (e.g. If the text says "...of Dr. N.G.P. Institute of Technology has participated...", the institution MUST be "Dr. N.G.P. Institute of Technology"). If it is a degree/course certificate issued directly by an institution, use the issuing institution name.
5. "organizer": Extract the organizing institution, department, or host college that conducted the event (e.g. "KPR Institute of Engineering and Technology", "Centre for Internet of Things").
6. "course": Extract the event name, symposium, workshop, competition, degree, or subject (e.g. "IGNITRON'26", "Full Stack Development").
7. "certificateId" / "registerNumber": Extract the certificate ID, register number, or roll number if visible.
8. "date": Extract the date(s) accurately (e.g. "18/09/2026 & 19/09/2026").
9. Ignore logos, decorative graphics, signatures and seals unless they contain readable required information.
10. Return JSON only. Do not add Markdown code fences. Do not add explanations outside the JSON.`;

    let rawText = '';
    let lastError = null;

    // Ordered list of candidate models for maximum reliability and speed
    const candidateModels = [
        'gemini-3.5-flash-lite',
        'gemini-3.6-flash',
        'gemini-3.1-flash-lite',
        'gemini-3.7-flash',
        'gemini-3.8-flash'
    ];

    const { GoogleGenAI } = require('@google/genai');
    const ai = new GoogleGenAI({ apiKey });

    for (const modelName of candidateModels) {
        try {
            console.log(`[GEMINI] Attempting extraction with model: ${modelName}...`);
            const response = await ai.models.generateContent({
                model: modelName,
                contents: [
                    {
                        role: 'user',
                        parts: [
                            { text: promptText },
                            {
                                inlineData: {
                                    mimeType: mimeType || 'image/jpeg',
                                    data: base64Data
                                }
                            }
                        ]
                    }
                ],
                config: {
                    responseMimeType: 'application/json'
                }
            });

            const text = response.text || (response.candidates && response.candidates[0]?.content?.parts?.[0]?.text) || '';
            if (text && text.trim().length > 0) {
                rawText = text;
                console.log(`[GEMINI] ✅ Successfully received response from ${modelName}`);
                break;
            }
        } catch (modelErr) {
            console.warn(`[GEMINI] Model ${modelName} failed (${modelErr.message}). Trying next candidate...`);
            lastError = modelErr;
        }
    }

    if (!rawText) {
        throw new Error(lastError ? lastError.message : 'All Gemini models failed to process the image.');
    }

    console.log(`[GEMINI] Response received`);
    console.log(`[GEMINI] Raw model output:`, rawText);

    // Clean JSON response (strip markdown fences if any)
    let cleanedJson = rawText.trim();
    if (cleanedJson.startsWith('```json')) {
        cleanedJson = cleanedJson.replace(/^```json\s*/i, '').replace(/```\s*$/, '').trim();
    } else if (cleanedJson.startsWith('```')) {
        cleanedJson = cleanedJson.replace(/^```\s*/i, '').replace(/```\s*$/, '').trim();
    }

    const parsed = JSON.parse(cleanedJson);

    return {
        name: (parsed.name || '').trim(),
        certificateId: (parsed.certificateId || parsed.certificate_id || parsed.registerNumber || '').trim(),
        registerNumber: (parsed.registerNumber || parsed.register_number || parsed.regNo || '').trim(),
        institution: (parsed.institution || parsed.institution_name || '').trim(),
        organizer: (parsed.organizer || parsed.organizer_name || parsed.organizedBy || '').trim(),
        course: (parsed.course || parsed.degree || parsed.program || '').trim(),
        date: (parsed.date || parsed.issueDate || '').trim()
    };
}

/**
 * Health check endpoint
 */
app.get('/api/health', (req, res) => {
    const hasKey = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'YOUR_GEMINI_API_KEY');
    res.json({
        status: 'online',
        geminiConfigured: hasKey,
        timestamp: new Date().toISOString()
    });
});

/**
 * Main OCR Endpoint
 * Accepts multipart/form-data (field: 'certificate') OR JSON { image: 'base64...', mimeType: '...' }
 */
app.post(['/api/ocr', '/ocr'], upload.single('certificate'), async (req, res) => {
    console.log(`[GEMINI] Upload received`);

    try {
        let fileBuffer = null;
        let mimeType = 'image/jpeg';
        let fileSize = 0;

        if (req.file) {
            fileBuffer = req.file.buffer;
            mimeType = req.file.mimetype || 'image/jpeg';
            fileSize = req.file.size;
        } else if (req.body && req.body.image) {
            let base64Str = req.body.image;
            if (base64Str.startsWith('data:')) {
                const match = base64Str.match(/^data:([^;]+);base64,(.+)$/);
                if (match) {
                    mimeType = match[1];
                    base64Str = match[2];
                }
            } else if (req.body.mimeType) {
                mimeType = req.body.mimeType;
            }
            fileBuffer = Buffer.from(base64Str, 'base64');
            fileSize = fileBuffer.length;
        } else {
            return res.status(400).json({
                success: false,
                error: 'No certificate file uploaded. Please send a file or base64 image.'
            });
        }

        console.log(`[GEMINI] File type: ${mimeType}`);
        console.log(`[GEMINI] File size: ${(fileSize / 1024).toFixed(2)} KB`);

        // Send to Gemini Vision API
        const extractedFields = await callGeminiVision(fileBuffer, mimeType);

        console.log(`[GEMINI] Parsed certificate fields:`, extractedFields);

        return res.json({
            success: true,
            source: 'gemini',
            data: extractedFields
        });

    } catch (error) {
        console.error(`[GEMINI] OCR Error:`, error.message);

        // Friendly error message
        let userMsg = 'Unable to process the certificate with Gemini Vision. Please try again or upload a clearer certificate.';
        if (error.message.includes('GEMINI_API_KEY')) {
            userMsg = 'Gemini API key is not configured in the backend .env file.';
        }

        return res.status(500).json({
            success: false,
            error: userMsg,
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Start Express server locally if not in Vercel serverless environment
if (!process.env.VERCEL) {
    app.listen(PORT, () => {
        console.log(`=======================================================`);
        console.log(`🚀 CertValid Backend Server running on http://localhost:${PORT}`);
        console.log(`📄 Gemini OCR Endpoint: http://localhost:${PORT}/api/ocr`);
        console.log(`🔑 Gemini API Key configured: ${Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'YOUR_GEMINI_API_KEY')}`);
        console.log(`=======================================================`);
    });
}

module.exports = app;
