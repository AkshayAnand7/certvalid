require('dotenv').config();
const { GoogleGenAI } = require('@google/genai');

async function listAllModels() {
    const apiKey = process.env.GEMINI_API_KEY;
    const ai = new GoogleGenAI({ apiKey });
    try {
        const response = await ai.models.list();
        console.log("=== AVAILABLE MODELS FOR YOUR KEY ===");
        for await (const m of response) {
            console.log(m.name, m.supportedActions || m.displayName);
        }
    } catch (e) {
        console.error("List models failed:", e.message);
    }
}

listAllModels();
