require('dotenv').config();
const { GoogleGenAI } = require('@google/genai');

async function checkQuotas() {
    const apiKey = process.env.GEMINI_API_KEY;
    const ai = new GoogleGenAI({ apiKey });

    // Test a wide variety of flash and lite models
    const testList = [
        'gemini-3.1-flash-lite',
        'gemini-3.5-flash-lite',
        'gemini-3.7-flash',
        'gemini-3.8-flash',
        'gemini-3.8-flash-lite',
        'gemini-3.5-flash',
        'gemini-3.6-flash',
        'gemini-3-flash-preview',
        'gemini-omni-1.1-flash',
        'gemma-4-31b-it',
        'gemma-4-26b-a4b-it'
    ];

    for (const model of testList) {
        try {
            const start = Date.now();
            const res = await ai.models.generateContent({
                model,
                contents: 'Respond with valid JSON: {"status": "ok", "model": "' + model + '"}',
                config: { responseMimeType: 'application/json' }
            });
            console.log(`✅ [${model}] WORKING (${Date.now() - start}ms):`, res.text.trim());
        } catch (err) {
            console.log(`❌ [${model}] ${err.status || ''}: ${err.message.substring(0, 120)}`);
        }
    }
}

checkQuotas();
