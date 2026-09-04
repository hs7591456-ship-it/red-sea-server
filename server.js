const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const admin = require("firebase-admin");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: "2mb" }));

const serviceAccount =
    require("/etc/secrets/serviceAccountKey.json");

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL:
        "https://red-sea-8db76-default-rtdb.firebaseio.com"
});

const db = admin.database();

const OWNER_FIREBASE_UID =
    process.env.OWNER_FIREBASE_UID || "";

const ADMIN_USERNAME =
    process.env.ADMIN_USERNAME || "";

const ADMIN_PASSWORD =
    process.env.ADMIN_PASSWORD || "";

/* =========================================================
   HELPERS
========================================================= */

function now() {
    return new Date().toISOString();
}

function clean(value) {
    return String(value ?? "").trim();
}

function generateId(length) {
    let result = "";

    for (let i = 0; i < length; i++) {
        result += Math.floor(Math.random() * 10);
    }

    return result;
}

async function generateUniqueId(path, length) {

    while (true) {

        const id = generateId(length);

        const snapshot =
            await db
                .ref(`${path}/${id}`)
                .once("value");

        if (!snapshot.exists()) {
            return id;
        }
    }
}

/* =========================================================
   PASSWORD SECURITY
========================================================= */

function createPasswordHash(password) {

    const salt =
        crypto
            .randomBytes(16)
            .toString("hex");

    const hash =
        crypto
            .scryptSync(password, salt, 64)
            .toString("hex");

    return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {

    try {

        const parts =
            String(storedHash).split(":");

        if (parts.length !== 2) {
            return false;
        }

        const salt = parts[0];
        const originalHash = parts[1];

        const calculatedHash =
            crypto
                .scryptSync(password, salt, 64)
                .toString("hex");

        const a =
            Buffer.from(originalHash, "hex");

        const b =
            Buffer.from(calculatedHash, "hex");

        if (a.length !== b.length) {
            return false;
        }

        return crypto.timingSafeEqual(a, b);

    } catch (error) {

        return false;
    }
}

/* =========================================================
   ADMIN SESSIONS
========================================================= */

const adminSessions = new Map();

function createAdminSession(data) {

    const token =
        crypto
            .randomBytes(48)
            .toString("hex");

    adminSessions.set(token, {
        ...data,
        createdAt: Date.now()
    });

    return token;
}

function getAdminSession(req) {

    const header =
        req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
        return null;
    }

    const token =
        header.substring(7);

    return adminSessions.get(token) || null;
}

function requireAdminSession(req, res, next) {

    const session =
        getAdminSession(req);

    if (!session) {

        return res.status(401).json({
            success: false,
            message: "Admin login required"
        });
    }

    req.adminSession = session;

    next();
}

function requireOwnerSession(req, res, next) {

    if (
        !req.adminSession ||
        req.adminSession.role !== "OWNER"
    ) {

        return res.status(403).json({
            success: false,
            message: "Owner permission required"
        });
    }

    next();
}

function hasPermission(session, permission) {

    if (!session) {
        return false;
    }

    if (session.role === "OWNER") {
        return true;
    }

    return (
        Array.isArray(session.permissions) &&
        session.permissions.includes(permission)
    );
}

function requireAdminPermission(permission) {

    return (req, res, next) => {

        if (!hasPermission(
            req.adminSession,
            permission
        )) {

            return res.status(403).json({
                success: false,
                message: "Permission denied"
            });
        }

        next();
    };
}

/* =========================================================
   USER HELPERS
========================================================= */

async function getUserByFirebaseUid(firebaseUid) {

    const snapshot =
        await db
            .ref("users")
            .orderByChild("firebaseUid")
            .equalTo(firebaseUid)
            .once("value");

    if (!snapshot.exists()) {
        return null;
    }

    const users =
        snapshot.val();

    const userId =
        Object.keys(users)[0];

    return {
        userId,
        ...users[userId]
    };
}

async function getUser(userId) {

    const snapshot =
        await db
            .ref(`users/${userId}`)
            .once("value");

    if (!snapshot.exists()) {
        return null;
    }

    return {
        userId,
        ...snapshot.val()
    };
}

/* =========================================================
   FIREBASE AUTH
========================================================= */

async function requireAuth(req, res, next) {

    try {

        const header =
            req.headers.authorization || "";

        if (!header.startsWith("Bearer ")) {

            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const token =
            header.substring(7);

        const decoded =
            await admin
                .auth()
                .verifyIdToken(token);

        const user =
            await getUserByFirebaseUid(
                decoded.uid
            );

        if (!user) {

            return res.status(403).json({
                success: false,
                message: "User profile not found"
            });
        }

        if (user.banned === true) {

            return res.status(403).json({
                success: false,
                message: "User is banned"
            });
        }

        req.firebaseUser = decoded;
        req.user = user;

        next();

    } catch (error) {

        console.error(
            "Auth error:",
            error.message
        );

        return res.status(401).json({
            success: false,
            message: "Invalid authentication"
        });
    }
}

function requireOwner(req, res, next) {

    if (
        req.user.role !== "OWNER" &&
        (
            !OWNER_FIREBASE_UID ||
            req.firebaseUser.uid !==
            OWNER_FIREBASE_UID
        )
    ) {

        return res.status(403).json({
            success: false,
            message: "Owner permission required"
        });
    }

    next();
}

function requireOwnerOrAdmin(req, res, next) {

    if (
        req.user.role !== "OWNER" &&
        req.user.role !== "ADMIN"
    ) {

        return res.status(403).json({
            success: false,
            message: "Admin permission required"
        });
    }

    next();
}

/* =========================================================
   BASIC
========================================================= */

app.get("/", (req, res) => {

    res.json({
        success: true,
        app: "Red Sea Server",
        status: "online"
    });
});

app.get("/api/status", async (req, res) => {

    try {

        await db
            .ref("server/status")
            .set({
                online: true,
                updatedAt: now()
            });

        res.json({
            success: true,
            message:
                "Red Sea API + Firebase are working",
            database: "connected",
            timestamp: now()
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            success: false,
            message:
                "Firebase connection failed"
        });
    }
});

/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post("/api/admin/login", async (req, res) => {

    try {

        const username =
            clean(req.body.username);

        const password =
            String(req.body.password || "");

        if (!username || !password) {

            return res.status(400).json({
                success: false,
                message:
                    "Username and password are required"
            });
        }

        /*
         * OWNER LOGIN
         * البيانات موجودة في Render فقط.
         */

        if (
            ADMIN_USERNAME &&
            username === ADMIN_USERNAME &&
            password === ADMIN_PASSWORD
        ) {

            const token =
                createAdminSession({
                    username,
                    role: "OWNER",
                    permissions: []
                });

            return res.json({
                success: true,
                role: "OWNER",
                username,
                token
            });
        }

        /*
         * ADMIN LOGIN
         */

        const snapshot =
            await db
                .ref("admins")
                .orderByChild("username")
                .equalTo(username)
                .once("value");

        if (!snapshot.exists()) {

            return res.status(401).json({
                success: false,
                message:
                    "Invalid username or password"
            });
        }

        const admins =
            snapshot.val();

        const adminId =
            Object.keys(admins)[0];

        const account =
            admins[adminId];

        if (account.active === false) {

            return res.status(403).json({
                success: false,
                message:
                    "Admin account is disabled"
            });
        }

        if (
            !verifyPassword(
                password,
                account.passwordHash
            )
        ) {

            return res.status(401).json({
                success: false,
                message:
                    "Invalid username or password"
            });
        }

        const permissions =
            Array.isArray(account.permissions)
                ? account.permissions
                : [];

        const token =
            createAdminSession({
                username:
                    account.username,
                role: "ADMIN",
                adminId,
                permissions
            });

        res.json({
            success: true,
            role: "ADMIN",
            username:
                account.username,
            adminId,
            permissions,
            token
        });

    } catch (error) {

        console.error(
            "Admin login error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Admin login failed"
        });
    }
});

app.post(
    "/api/admin/logout",
    requireAdminSession,
    (req, res) => {

        const header =
            req.headers.authorization || "";

        const token =
            header.substring(7);

        adminSessions.delete(token);

        res.json({
            success: true,
            message: "Logged out"
        });
    }
);

app.get(
    "/api/admin/me",
    requireAdminSession,
    (req, res) => {

        res.json({
            success: true,
            admin: {
                username:
                    req.adminSession.username,
                role:
                    req.adminSession.role,
                adminId:
                    req.adminSession.adminId ||
                    null,
                permissions:
                    req.adminSession.permissions ||
                    []
            }
        });
    }
);

/* =========================================================
   OWNER - ADMIN MANAGEMENT
========================================================= */

app.get(
    "/api/owner/admins",
    requireAdminSession,
    requireOwnerSession,
    async (req, res) => {

        try {

            const snapshot =
                await db
                    .ref("admins")
                    .once("value");

            const data =
                snapshot.val() || {};

            const admins =
                Object.entries(data)
                    .map(([adminId, item]) => ({
                        adminId,
                        username:
                            item.username,
                        role:
                            item.role ||
                            "ADMIN",
                        permissions:
                            item.permissions ||
                            [],
                        active:
                            item.active !== false,
                        createdAt:
                            item.createdAt ||
                            null
                    }));

            res.json({
                success: true,
                admins
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Failed to load admins"
            });
        }
    }
);

app.post(
    "/api/owner/admins",
    requireAdminSession,
    requireOwnerSession,
    async (req, res) => {

        try {

            const username =
                clean(req.body.username);

            const password =
                String(req.body.password || "");

            const permissions =
                Array.isArray(
                    req.body.permissions
                )
                    ? req.body.permissions
                        .map(clean)
                        .filter(Boolean)
                    : [];

            if (!username || !password) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Username and password are required"
                });
            }

            if (
                username.length < 3 ||
                password.length < 6
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Username must be 3+ chars and password 6+ chars"
                });
            }

            if (
                ADMIN_USERNAME &&
                username === ADMIN_USERNAME
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "This username is reserved"
                });
            }

            const existing =
                await db
                    .ref("admins")
                    .orderByChild("username")
                    .equalTo(username)
                    .once("value");

            if (existing.exists()) {

                return res.status(409).json({
                    success: false,
                    message:
                        "Username already exists"
                });
            }

            const adminId =
                await generateUniqueId(
                    "admins",
                    8
                );

            const account = {

                adminId,

                username,

                passwordHash:
                    createPasswordHash(password),

                role: "ADMIN",

                permissions,

                active: true,

                createdAt: now(),

                createdBy:
                    req.adminSession.username
            };

            await db
                .ref(`admins/${adminId}`)
                .set(account);

            res.json({

                success: true,

                admin: {

                    adminId,

                    username,

                    role: "ADMIN",

                    permissions,

                    active: true,

                    createdAt:
                        account.createdAt
                }
            });

        } catch (error) {

            console.error(
                "Create admin error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Failed to create admin"
            });
        }
    }
);

app.patch(
    "/api/owner/admins/:adminId",
    requireAdminSession,
    requireOwnerSession,
    async (req, res) => {

        try {

            const ref =
                db.ref(
                    `admins/${req.params.adminId}`
                );

            const snapshot =
                await ref.once("value");

            if (!snapshot.exists()) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Admin not found"
                });
            }

            const updates = {};

            if (
                req.body.username !==
                undefined
            ) {

                const username =
                    clean(
                        req.body.username
                    );

                if (username.length < 3) {

                    return res.status(400).json({
                        success: false,
                        message:
                            "Invalid username"
                    });
                }

                updates.username =
                    username;
            }

            if (
                req.body.password !==
                undefined
            ) {

                const password =
                    String(
                        req.body.password
                    );

                if (password.length < 6) {

                    return res.status(400).json({
                        success: false,
                        message:
                            "Password must be 6+ chars"
                    });
                }

                updates.passwordHash =
                    createPasswordHash(
                        password
                    );
            }

            if (
                req.body.permissions !==
                undefined
            ) {

                if (
                    !Array.isArray(
                        req.body.permissions
                    )
                ) {

                    return res.status(400).json({
                        success: false,
                        message:
                            "permissions must be an array"
                    });
                }

                updates.permissions =
                    req.body.permissions
                        .map(clean)
                        .filter(Boolean);
            }

            if (
                req.body.active !==
                undefined
            ) {

                updates.active =
                    req.body.active === true;
            }

            if (
                !Object.keys(updates).length
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "No valid fields to update"
                });
            }

            updates.updatedAt = now();

            await ref.update(updates);

            /*
             * إسقاط الجلسات القديمة لهذا المدير
             * حتى تدخل الصلاحيات الجديدة.
             */

            for (
                const [token, session]
                of adminSessions.entries()
            ) {

                if (
                    session.adminId ===
                    req.params.adminId
                ) {

                    adminSessions.delete(
                        token
                    );
                }
            }

            res.json({
                success: true,
                message:
                    "Admin updated successfully"
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Failed to update admin"
            });
        }
    }
);

app.delete(
    "/api/owner/admins/:adminId",
    requireAdminSession,
    requireOwnerSession,
    async (req, res) => {

        try {

            await db
                .ref(
                    `admins/${req.params.adminId}`
                )
                .remove();

            for (
                const [token, session]
                of adminSessions.entries()
            ) {

                if (
                    session.adminId ===
                    req.params.adminId
                ) {

                    adminSessions.delete(token);
                }
            }

            res.json({
                success: true,
                message:
                    "Admin deleted successfully"
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Failed to delete admin"
            });
        }
    }
);

/* =========================================================
   USERS
========================================================= */

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
                message:
                    "firebaseUid is required"
            });
        }

        const existing =
            await getUserByFirebaseUid(
                firebaseUid
            );

        if (existing) {

            return res.json({
                success: true,
                message:
                    "User already exists",
                userId:
                    existing.userId,
                user:
                    existing
            });
        }

        const userId =
            await generateUniqueId(
                "users",
                8
            );

        const role =
            OWNER_FIREBASE_UID &&
            firebaseUid ===
            OWNER_FIREBASE_UID
                ? "OWNER"
                : "USER";

        const userData = {

            userId,

            firebaseUid,

            name:
                clean(name),

            email:
                clean(email),

            coins: 0,

            agencyId: null,

            role,

            banned: false,

            createdAt:
                now()
        };

        await db
            .ref(`users/${userId}`)
            .set(userData);

        res.json({

            success: true,

            message:
                "User created successfully",

            userId,

            user:
                userData
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            success: false,
            message:
                "Failed to create user"
        });
    }
});

app.get(
    "/api/users/by-firebase/:firebaseUid",
    async (req, res) => {

        try {

            const user =
                await getUserByFirebaseUid(
                    req.params.firebaseUid
                );

            if (!user) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User not found"
                });
            }

            res.json({
                success: true,
                user
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Failed to get user"
            });
        }
    }
);

app.get(
    "/api/users/:userId",
    requireAuth,
    async (req, res) => {

        try {

            const user =
                await getUser(
                    req.params.userId
                );

            if (!user) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User not found"
                });
            }

            res.json({
                success: true,
                user
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Failed to get user"
            });
        }
    }
);

app.patch(
    "/api/users/:userId",
    requireAuth,
    async (req, res) => {

        try {

            if (
                req.user.userId !==
                req.params.userId &&
                req.user.role !== "OWNER" &&
                req.user.role !== "ADMIN"
            ) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Permission denied"
                });
            }

            const ref =
                db.ref(
                    `users/${req.params.userId}`
                );

            const snapshot =
                await ref.once("value");

            if (!snapshot.exists()) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User not found"
                });
            }

            const updates = {};

            if (
                req.body.name !==
                undefined
            ) {

                updates.name =
                    clean(req.body.name);
            }

            if (
                !Object.keys(updates).length
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "No valid fields to update"
                });
            }

            updates.updatedAt = now();

            await ref.update(updates);

            res.json({
                success: true,
                user:
                    await getUser(
                        req.params.userId
                    )
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Failed to update user"
            });
        }
    }
);

/* =========================================================
   ROOMS
========================================================= */

async function getRoom(roomId) {

    const snapshot =
        await db
            .ref(`rooms/${roomId}`)
            .once("value");

    if (!snapshot.exists()) {
        return null;
    }

    return {
        roomId,
        ...snapshot.val()
    };
}

app.get("/api/rooms", async (req, res) => {

    try {

        const snapshot =
            await db
                .ref("rooms")
                .once("value");

        const data =
            snapshot.val() || {};

        const rooms =
            Object.entries(data)

                .map(([roomId, room]) => ({
                    roomId,
                    ...room
                }))

                .filter(room =>
                    room.deleted !== true &&
                    room.active !== false
                )

                .sort((a, b) =>
                    Number(
                        b.activityCoins ||
                        b.coins ||
                        0
                    )
                    -
                    Number(
                        a.activityCoins ||
                        a.coins ||
                        0
                    )
                );

        res.json({
            success: true,
            rooms
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            success: false,
            message:
                "Failed to load rooms"
        });
    }
});

app.post(
    "/api/rooms",
    requireAuth,
    async (req, res) => {

        try {

            const name =
                clean(req.body.name);

            const description =
                clean(req.body.description);

            if (!name) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Room name is required"
                });
            }

            const roomId =
                await generateUniqueId(
                    "rooms",
                    6
                );

            const room = {

                roomId,

                name,

                description,

                ownerId:
                    req.user.userId,

                agencyId:
                    req.user.agencyId ||
                    null,

                membersCount: 0,

                activityCoins: 0,

                members: {},

                active: true,

                deleted: false,

                createdAt:
                    now()
            };

            await db
                .ref(`rooms/${roomId}`)
                .set(room);

            res.json({
                success: true,
                room
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Failed to create room"
            });
        }
    }
);

app.get(
    "/api/rooms/:roomId",
    async (req, res) => {

        try {

            const room =
                await getRoom(
                    req.params.roomId
                );

            if (
                !room ||
                room.deleted === true
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Room not found"
                });
            }

            res.json({
                success: true,
                room
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message:
                    "Failed to load room"
            });
        }
    }
);

app.post(
    "/api/rooms/:roomId/join",
    requireAuth,
    async (req, res) => {

        try {

            const room =
                await getRoom(
                    req.params.roomId
                );

            if (
                !room ||
                room.deleted === true ||
                room.active === false
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Room not found"
                });
            }

            const memberRef =
                db.ref(
                    `rooms/${req.params.roomId}/members/${req.user.userId}`
                );

            const existing =
                await memberRef.once("value");

            if (!existing.exists()) {

                await memberRef.set({
                    userId:
                        req.user.userId,
                    name:
                        req.user.name || "",
                    joinedAt:
                        now()
                });

                await db
                    .ref(
                        `rooms/${req.params.roomId}/membersCount`
                    )
                    .transaction(
                        value =>
                            Number(value || 0) + 1
                    );
            }

            res.json({
                success: true,
                joined: true
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Failed to join room"
            });
        }
    }
);

app.post(
    "/api/rooms/:roomId/leave",
    requireAuth,
    async (req, res) => {

        try {

            const memberRef =
                db.ref(
                    `rooms/${req.params.roomId}/members/${req.user.userId}`
                );

            const existing =
                await memberRef.once("value");

            if (existing.exists()) {

                await memberRef.remove();

                await db
                    .ref(
                        `rooms/${req.params.roomId}/membersCount`
                    )
                    .transaction(
                        value =>
                            Math.max(
                                0,
                                Number(value || 0) - 1
                            )
                    );
            }

            res.json({
                success: true,
                joined: false
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message:
                    "Failed to leave room"
            });
        }
    }
);

app.get(
    "/api/rooms/:roomId/members",
    requireAuth,
    async (req, res) => {

        try {

            const room =
                await getRoom(
                    req.params.roomId
                );

            if (!room) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Room not found"
                });
            }

            if (
                room.ownerId !==
                req.user.userId &&
                req.user.role !== "OWNER" &&
                req.user.role !== "ADMIN"
            ) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Room owner permission required"
                });
            }

            const snapshot =
                await db
                    .ref(
                        `rooms/${req.params.roomId}/members`
                    )
                    .once("value");

            const members =
                Object.entries(
                    snapshot.val() || {}
                )
                    .map(
                        ([userId, member]) => ({
                            userId,
                            ...member
                        })
                    );

            res.json({
                success: true,
                roomId:
                    req.params.roomId,
                members
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message:
                    "Failed to load room members"
            });
        }
    }
);

app.patch(
    "/api/rooms/:roomId",
    requireAuth,
    async (req, res) => {

        try {

            const room =
                await getRoom(
                    req.params.roomId
                );

            if (!room) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Room not found"
                });
            }

            const canManage =
                room.ownerId ===
                req.user.userId ||
                req.user.role ===
                "OWNER" ||
                req.user.role ===
                "ADMIN";

            if (!canManage) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Room management permission required"
                });
            }

            const updates = {};

            if (
                req.body.name !==
                undefined
            ) {

                updates.name =
                    clean(req.body.name);
            }

            if (
                req.body.description !==
                undefined
            ) {

                updates.description =
                    clean(
                        req.body.description
                    );
            }

            if (
                req.body.active !==
                undefined &&
                (
                    req.user.role ===
                    "OWNER" ||
                    req.user.role ===
                    "ADMIN"
                )
            ) {

                updates.active =
                    req.body.active === true;
            }

            if (
                !Object.keys(updates).length
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "No valid fields to update"
                });
            }

            updates.updatedAt = now();

            await db
                .ref(
                    `rooms/${req.params.roomId}`
                )
                .update(updates);

            res.json({
                success: true,
                room:
                    await getRoom(
                        req.params.roomId
                    )
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Failed to update room"
            });
        }
    }
);

app.delete(
    "/api/rooms/:roomId",
    requireAuth,
    async (req, res) => {

        try {

            const room =
                await getRoom(
                    req.params.roomId
                );

            if (!room) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Room not found"
                });
            }

            if (
                room.ownerId !==
                req.user.userId &&
                req.user.role !==
                "OWNER" &&
                req.user.role !==
                "ADMIN"
            ) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Room management permission required"
                });
            }

            await db
                .ref(
                    `rooms/${req.params.roomId}`
                )
                .update({
                    deleted: true,
                    active: false,
                    deletedAt: now(),
                    deletedBy:
                        req.user.userId
                });

            res.json({
                success: true,
                message:
                    "Room deleted successfully"
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message:
                    "Failed to delete room"
            });
        }
    }
);

/* =========================================================
   FOLLOWING
========================================================= */

app.post(
    "/api/rooms/:roomId/follow",
    requireAuth,
    async (req, res) => {

        try {

            const room =
                await getRoom(
                    req.params.roomId
                );

            if (
                !room ||
                room.deleted === true
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Room not found"
                });
            }

            const ref =
                db.ref(
                    `users/${req.user.userId}/followingRooms/${req.params.roomId}`
                );

            const current =
                await ref.once("value");

            if (current.exists()) {

                await ref.remove();

                return res.json({
                    success: true,
                    following: false
                });
            }

            await ref.set({
                roomId:
                    req.params.roomId,
                followedAt:
                    now()
            });

            res.json({
                success: true,
                following: true
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message:
                    "Failed to update follow"
            });
        }
    }
);

app.get(
    "/api/rooms/following",
    requireAuth,
    async (req, res) => {

        try {

            const snapshot =
                await db
                    .ref(
                        `users/${req.user.userId}/followingRooms`
                    )
                    .once("value");

            const following =
                snapshot.val() || {};

            const rooms = [];

            for (
                const roomId
                of Object.keys(following)
            ) {

                const room =
                    await getRoom(roomId);

                if (
                    room &&
                    room.deleted !== true &&
                    room.active !== false
                ) {

                    rooms.push({
                        ...room,
                        isFollowing: true
                    });
                }
            }

            res.json({
                success: true,
                rooms
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message:
                    "Failed to load following rooms"
            });
        }
    }
);

/* =========================================================
   AGENCIES
========================================================= */

app.get(
    "/api/agencies/top",
    async (req, res) => {

        try {

            const limit =
                Math.min(
                    Math.max(
                        Number(
                            req.query.limit ||
                            4
                        ),
                        1
                    ),
                    20
                );

            const snapshot =
                await db
                    .ref("agencies")
                    .once("value");

            const data =
                snapshot.val() || {};

            const agencies =
                Object.entries(data)

                    .map(
                        ([agencyId, agency]) => ({
                            agencyId,
                            ...agency
                        })
                    )

                    .filter(agency =>
                        agency.deleted !== true &&
                        agency.active !== false &&
                        agency.type !==
                        "SHIPPING"
                    )

                    .sort((a, b) =>
                        Number(
                            b.activityCoins ||
                            b.coins ||
                            0
                        )
                        -
                        Number(
                            a.activityCoins ||
                            a.coins ||
                            0
                        )
                    )

                    .slice(0, limit);

            res.json({
                success: true,
                agencies
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message:
                    "Failed to load agencies"
            });
        }
    }
);

app.post(
    "/api/agencies",
    requireAuth,
    requireOwnerOrAdmin,
    async (req, res) => {

        try {

            const name =
                clean(req.body.name);

            if (!name) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Agency name is required"
                });
            }

            const agencyId =
                await generateUniqueId(
                    "agencies",
                    6
                );

            const agency = {

                agencyId,

                name,

                type: "NORMAL",

                ownerId:
                    req.user.userId,

                coins: 0,

                activityCoins: 0,

                totalSupport: 0,

                membersCount: 0,

                members: {},

                active: true,

                deleted: false,

                createdAt:
                    now()
            };

            await db
                .ref(`agencies/${agencyId}`)
                .set(agency);

            res.json({
                success: true,
                agency
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Failed to create agency"
            });
        }
    }
);

app.get(
    "/api/agencies/:agencyId",
    async (req, res) => {

        try {

            const snapshot =
                await db
                    .ref(
                        `agencies/${req.params.agencyId}`
                    )
                    .once("value");

            if (!snapshot.exists()) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Agency not found"
                });
            }

            res.json({
                success: true,
                agency: {
                    agencyId:
                        req.params.agencyId,
                    ...snapshot.val()
                }
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message:
                    "Failed to load agency"
            });
        }
    }
);

/* =========================================================
   AGENCY MEMBERS
========================================================= */

app.post(
    "/api/agencies/:agencyId/members",
    requireAuth,
    async (req, res) => {

        try {

            const agencyRef =
                db.ref(
                    `agencies/${req.params.agencyId}`
                );

            const agencySnapshot =
                await agencyRef.once("value");

            if (!agencySnapshot.exists()) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Agency not found"
                });
            }

            const agency =
                agencySnapshot.val();

            if (
                agency.ownerId !==
                req.user.userId &&
                req.user.role !==
                "OWNER" &&
                req.user.role !==
                "ADMIN"
            ) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Agency owner permission required"
                });
            }

            const userId =
                clean(req.body.userId);

            if (!/^\d{8}$/.test(userId)) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid user ID"
                });
            }

            const userRef =
                db.ref(`users/${userId}`);

            const userSnapshot =
                await userRef.once("value");

            if (!userSnapshot.exists()) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User not found"
                });
            }

            const user =
                userSnapshot.val();

            if (
                user.agencyId &&
                user.agencyId !==
                req.params.agencyId
            ) {

                return res.status(409).json({
                    success: false,
                    message:
                        "User already belongs to another agency"
                });
            }

            const memberRef =
                agencyRef
                    .child("members")
                    .child(userId);

            const memberExists =
                await memberRef.once("value");

            await userRef.update({
                agencyId:
                    req.params.agencyId,
                updatedAt:
                    now()
            });

            if (!memberExists.exists()) {

                await memberRef.set({
                    userId,
                    name:
                        user.name || "",
                    joinedAt:
                        now()
                });

                await agencyRef
                    .child("membersCount")
                    .transaction(
                        value =>
                            Number(value || 0) + 1
                    );
            }

            res.json({
                success: true,
                message:
                    "User added to agency",
                userId,
                agencyId:
                    req.params.agencyId
            });

        } catch (error