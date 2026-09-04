const express = require("express");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// الصفحة الرئيسية للسيرفر
app.get("/", (req, res) => {
    res.json({
        success: true,
        app: "Red Sea Server",
        status: "online"
    });
});

// اختبار API
app.get("/api/status", (req, res) => {
    res.json({
        success: true,
        message: "Red Sea API is working",
        timestamp: new Date().toISOString()
    });
});

// تشغيل السيرفر
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Red Sea Server running on port ${PORT}`);
});
