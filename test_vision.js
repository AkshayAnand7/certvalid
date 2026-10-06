require('dotenv').config();
const { GoogleGenAI } = require('@google/genai');

async function testVision() {
    const apiKey = process.env.GEMINI_API_KEY;
    const ai = new GoogleGenAI({ apiKey });
    
    // Sample base64 1x1 transparent PNG
    const dummyBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

    const models = ['gemini-3.5-flash-lite', 'gemini-3.6-flash', 'gemini-3.1-flash-lite'];

    for (const m of models) {
        try {
            const start = Date.now();
            const res = await ai.models.generateContent({
                model: m,
                contents: [
                    {
                        role: 'user',
                        parts: [
                            { text: 'Return JSON: {"status": "ok"}' },
                            { inlineData: { mimeType: 'image/png', data: dummyBase64 } }
                        ]
                    }
                ],
                config: { responseMimeType: 'application/json' }
            });
            console.log(`✅ [${m}] VISION WORKING in ${Date.now() - start}ms:`, res.text.trim());
        } catch (e) {
            console.log(`❌ [${m}] Vision failed:`, e.message);
        }
    }
}

testVision();
