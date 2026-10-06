const { GoogleGenAI } = require('@google/genai');

module.exports = async function handler(req, res) {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader(
        'Access-Control-Allow-Headers',
        'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
    );

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, error: 'Method Not Allowed' });
    }

    try {
        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey || apiKey.trim() === '' || apiKey === 'YOUR_GEMINI_API_KEY') {
            console.error('[GEMINI] Missing GEMINI_API_KEY environment variable');
            return res.status(500).json({
                success: false,
                error: 'GEMINI_API_KEY is not configured in Vercel Environment Variables. Please set it in Vercel Dashboard -> Settings -> Environment Variables.'
            });
        }

        let base64Data = '';
        let mimeType = 'image/jpeg';

        if (req.body && req.body.image) {
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
            base64Data = base64Str;
        }

        if (!base64Data) {
            return res.status(400).json({
                success: false,
                error: 'No image data provided. Expected JSON with { image: "base64..." }'
            });
        }

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

        const candidateModels = [
            'gemini-3.5-flash-lite',
            'gemini-3.6-flash',
            'gemini-3.1-flash-lite',
            'gemini-3.7-flash',
            'gemini-3.8-flash'
        ];

        const ai = new GoogleGenAI({ apiKey });
        let rawText = '';
        let lastError = null;

        for (const modelName of candidateModels) {
            try {
                console.log(`[GEMINI] Trying model: ${modelName}`);
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
                    console.log(`[GEMINI] ✅ Succeeded with model: ${modelName}`);
                    break;
                }
            } catch (err) {
                console.warn(`[GEMINI] Model ${modelName} failed:`, err.message);
                lastError = err;
            }
        }

        if (!rawText) {
            throw new Error(lastError ? lastError.message : 'All Gemini models failed to process image.');
        }

        const cleanJson = rawText.replace(/```(?:json)?/gi, '').replace(/```/g, '').trim();
        const parsed = JSON.parse(cleanJson);

        return res.status(200).json({
            success: true,
            source: 'gemini',
            data: {
                name: (parsed.name || '').trim(),
                certificateId: (parsed.certificateId || parsed.certificate_id || parsed.registerNumber || '').trim(),
                registerNumber: (parsed.registerNumber || parsed.register_number || parsed.regNo || '').trim(),
                institution: (parsed.institution || parsed.institution_name || '').trim(),
                organizer: (parsed.organizer || parsed.organizer_name || parsed.organizedBy || '').trim(),
                course: (parsed.course || parsed.degree || parsed.program || '').trim(),
                date: (parsed.date || parsed.issueDate || '').trim()
            }
        });
    } catch (err) {
        console.error('[GEMINI] Serverless function error:', err);
        return res.status(500).json({
            success: false,
            error: err.message || 'Unable to process certificate with Gemini Vision.'
        });
    }
};
