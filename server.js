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
// Helpers
// =========================

// إنشاء رقم ID عشوائي
function generateId(length) {
    let result = "";

    for (let i = 0; i < length; i++) {
        result += Math.floor(Math.random() * 10);
    }

    return result;
}

// التأكد إن الـ ID غير مستخدم
async function generateUniqueId(path, length) {
    let id;
    let exists = true;

    while (exists) {
        id = generateId(length);

        const snapshot = await db.ref(`${path}/${id}`).once("value");

        exists = snapshot.exists();
    }

    return id;
}

// =========================
// Home
// =========================
app.get("/", (req, res) => {
    res.json({
        success: true,
        app: "Red Sea Server",
        status: "online"
    });
});

// =========================
// API Status
// =========================
app.get("/api/status", async (req, res) => {
    try {
        await db.ref("server/status").set({
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
// Create User
// =========================
// POST /api/users
//
// Body:
// {
//   "firebaseUid": "...",
//   "name": "...",
//   "email": "..."
// }

app.post("/api/users", async (req, res) => {
    try {
        const {
            firebaseUid,
            name,
            email
        } = req.body;

        if (!firebaseUid) {
            return res.status(400).json({
                success: false,
                message: "firebaseUid is required"
            });
        }

        // هل الحساب موجود بالفعل؟
        const existingSnapshot = await db
            .ref("users")
            .orderByChild("firebaseUid")
            .equalTo(firebaseUid)
            .once("value");

        if (existingSnapshot.exists()) {
            const users = existingSnapshot.val();
            const existingId = Object.keys(users)[0];

            return res.json({
                success: true,
                message: "User already exists",
                userId: existingId,
                user: users[existingId]
            });
        }

        // إنشاء User ID من 8 أرقام
        const userId = await generateUniqueId("users", 8);

        const userData = {
            userId: userId,
            firebaseUid: firebaseUid,
            name: name || "",
            email: email || "",
            coins: 0,
            agencyId: null,
            role: "USER",
            createdAt: new Date().toISOString()
        };

        await db.ref(`users/${userId}`).set(userData);

        res.json({
            success: true,
            message: "User created successfully",
            userId: userId,
            user: userData
        });

    } catch (error) {
        console.error("Create user error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to create user",
            error: error.message
        });
    }
});

// =========================
// Get User
// =========================
// GET /api/users/:userId

app.get("/api/users/:userId", async (req, res) => {
    try {
        const userId = req.params.userId;

        const snapshot = await db
            .ref(`users/${userId}`)
            .once("value");

        if (!snapshot.exists()) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        res.json({
            success: true,
            user: snapshot.val()
        });

    } catch (error) {
        console.error("Get user error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to get user"
        });
    }
});

// =========================
// Update User
// =========================
// PATCH /api/users/:userId
//
// Body:
// {
//   "name": "New Name"
// }

app.patch("/api/users/:userId", async (req, res) => {
    try {
        const userId = req.params.userId;

        const snapshot = await db
            .ref(`users/${userId}`)
            .once("value");

        if (!snapshot.exists()) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        const allowedFields = [
            "name"
        ];

        const updates = {};

        for (const field of allowedFields) {
            if (req.body[field] !== undefined) {
                updates[field] = req.body[field];
            }
        }

        if (Object.keys(updates).length === 0) {
            return res.status(400).json({
                success: false,
                message: "No valid fields to update"
            });
        }

        updates.updatedAt = new Date().toISOString();

        await db
            .ref(`users/${userId}`)
            .update(updates);

        const updatedSnapshot = await db
            .ref(`users/${userId}`)
            .once("value");

        res.json({
            success: true,
            message: "User updated successfully",
            user: updatedSnapshot.val()
        });

    } catch (error) {
        console.error("Update user error:", error);

        res.status(500).json({
            success: false,
            message: "Failed to update user"
        });
    }
});

// =========================
// Start Server
// =========================
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Red Sea Server running on port ${PORT}`);
});
