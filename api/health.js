module.exports = function handler(req, res) {
    const hasKey = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'YOUR_GEMINI_API_KEY');
    res.status(200).json({
        status: 'online',
        geminiConfigured: hasKey,
        envSet: hasKey ? 'YES' : 'NO - Please add GEMINI_API_KEY in Vercel Dashboard Settings',
        timestamp: new Date().toISOString()
    });
};
