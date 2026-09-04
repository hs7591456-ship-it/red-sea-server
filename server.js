const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

const app = express();
const PORT = process.env.PORT || 3000;

// =========================
// Middleware
// =========================
app.use(cors());
app.use(express.json());

// =========================
// Firebase Admin
// =========================
const serviceAccount = require("/etc/secrets/serviceAccountKey.json");

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://red-sea-8db76-default-rtdb.firebaseio.com"
});

const db = admin.database();

// =========================
// Home
// =========================
app.get("/", (req, res) => {
    res.json({
        success: true,
        app: "Red Sea Server",
        status: "online",
        database: "connected"
    });
});

// =========================
// API Status
// =========================
app.get("/api/status", async (req, res) => {
    try {
        const ref = db.ref("server/status");

        await ref.set({
            online: true,
            updatedAt: new Date().toISOString()
        });

        res.json({
            success: true,
            message: "Red Sea API + Firebase are working",
            database: "connected",
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error("Firebase error:", error);

        res.status(500).json({
            success: false,
            message: "Firebase connection failed"
        });
    }
});

// =========================
// Start Server
// =========================
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Red Sea Server running on port ${PORT}`);
});
