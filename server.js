const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const admin = require("firebase-admin");

const app = express();

const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: "2mb" }));

/* =========================================================
   FIREBASE
========================================================= */

const serviceAccount =
    require("/etc/secrets/serviceAccountKey.json");

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL:
        "https://red-sea-8db76-default-rtdb.firebaseio.com"
});

const db = admin.database();

/* =========================================================
   ENV
========================================================= */

const OWNER_FIREBASE_UID =
    process.env.OWNER_FIREBASE_UID || "";

const ADMIN_USERNAME =
    process.env.ADMIN_USERNAME || "";

const ADMIN_PASSWORD =
    process.env.ADMIN_PASSWORD || "";

const ADMIN_SESSION_DAYS =
    Number(process.env.ADMIN_SESSION_DAYS || 7);

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
   PASSWORD HASH
========================================================= */

function createPasswordHash(password) {
    const salt =
        crypto.randomBytes(16).toString("hex");

    const hash =
        crypto
            .scryptSync(password, salt, 64)
            .toString("hex");

    return {
        salt,
        hash
    };
}

function verifyPassword(
    password,
    storedHash,
    storedSalt
) {
    try {
        if (
            !password ||
            !storedHash ||
            !storedSalt
        ) {
            return false;
        }

        const hash =
            crypto.scryptSync(
                password,
                storedSalt,
                64
            );

        const stored =
            Buffer.from(
                storedHash,
                "hex"
            );

        if (
            hash.length !==
            stored.length
        ) {
            return false;
        }

        return crypto.timingSafeEqual(
            hash,
            stored
        );
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

    const expiresAt =
        Date.now() +
        ADMIN_SESSION_DAYS *
        24 *
        60 *
        60 *
        1000;

    adminSessions.set(token, {
        ...data,
        createdAt: Date.now(),
        expiresAt
    });

    return token;
}

function getAdminSession(token) {
    if (!token) {
        return null;
    }

    const session =
        adminSessions.get(token);

    if (!session) {
        return null;
    }

    if (
        Date.now() >
        session.expiresAt
    ) {
        adminSessions.delete(token);
        return null;
    }

    return session;
}

function deleteAdminSession(token) {
    if (token) {
        adminSessions.delete(token);
    }
}

function getAdminToken(req) {
    const header =
        req.headers.authorization || "";

    if (header.startsWith("Admin ")) {
        return header
            .substring(6)
            .trim();
    }

    if (header.startsWith("Bearer ")) {
        return header
            .substring(7)
            .trim();
    }

    return "";
}

/* =========================================================
   ADMIN AUTH MIDDLEWARE
========================================================= */

function requireAdminSession(
    req,
    res,
    next
) {
    const token =
        getAdminToken(req);

    const session =
        getAdminSession(token);

    if (!session) {
        return res.status(401).json({
            success: false,
            message:
                "Admin authentication required"
        });
    }

    req.adminSession = session;

    next();
}

function requireOwnerSession(
    req,
    res,
    next
) {
    if (
        !req.adminSession ||
        req.adminSession.role !==
            "OWNER"
    ) {
        return res.status(403).json({
            success: false,
            message:
                "Owner permission required"
        });
    }

    next();
}

function hasPermission(
    session,
    permission
) {
    if (!session) {
        return false;
    }

    if (session.role === "OWNER") {
        return true;
    }

    return (
        Array.isArray(
            session.permissions
        ) &&
        session.permissions.includes(
            permission
        )
    );
}

function requireAdminPermission(
    permission
) {
    return function (
        req,
        res,
        next
    ) {
        if (
            !req.adminSession ||
            !hasPermission(
                req.adminSession,
                permission
            )
        ) {
            return res.status(403).json({
                success: false,
                message:
                    "Permission denied"
            });
        }

        next();
    };
}

/* =========================================================
   FIREBASE AUTH
========================================================= */

async function getUserByFirebaseUid(
    firebaseUid
) {
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

async function requireAuth(
    req,
    res,
    next
) {
    try {
        const header =
            req.headers.authorization ||
            "";

        if (
            !header.startsWith(
                "Bearer "
            )
        ) {
            return res.status(401).json({
                success: false,
                message:
                    "Authentication required"
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
                message:
                    "User profile not found"
            });
        }

        if (user.banned === true) {
            return res.status(403).json({
                success: false,
                message:
                    "User is banned"
            });
        }

        req.firebaseUser = decoded;
        req.user = user;

        next();
    } catch (error) {
        console.error(
            "Firebase auth error:",
            error.message
        );

        return res.status(401).json({
            success: false,
            message:
                "Invalid authentication"
        });
    }
}

function requireOwner(
    req,
    res,
    next
) {
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
            message:
                "Owner permission required"
        });
    }

    next();
}

function requireOwnerOrAdmin(
    req,
    res,
    next
) {
    if (
        req.user.role !== "OWNER" &&
        req.user.role !== "ADMIN"
    ) {
        return res.status(403).json({
            success: false,
            message:
                "Admin permission required"
        });
    }

    next();
}

/* =========================================================
   BASIC
========================================================= */

app.get(
    "/",
    (req, res) => {
        res.json({
            success: true,
            app: "Red Sea Server",
            status: "online"
        });
    }
);

app.get(
    "/api/status",
    async (req, res) => {
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
                database:
                    "connected",
                timestamp:
                    now()
            });
        } catch (error) {
            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Firebase connection failed"
            });
        }
    }
);

/* =========================================================
   SEPARATE ADMIN LOGIN
========================================================= */

app.post(
    "/api/admin/login",
    async (req, res) => {
        try {
            const username =
                clean(
                    req.body.username
                );

            const password =
                String(
                    req.body.password ||
                    ""
                );

            if (
                !username ||
                !password
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Username and password are required"
                });
            }

            /* OWNER */

            if (
                ADMIN_USERNAME &&
                ADMIN_PASSWORD &&
                username ===
                    ADMIN_USERNAME &&
                password ===
                    ADMIN_PASSWORD
            ) {
                const token =
                    createAdminSession({
                        role:
                            "OWNER",
                        username,
                        name:
                            "Owner",
                        permissions: [
                            "users",
                            "rooms",
                            "agencies",
                            "ads",
                            "banUsers",
                            "transactions",
                            "shipping",
                            "reports",
                            "admins"
                        ]
                    });

                return res.json({
                    success: true,
                    role: "OWNER",
                    name: "Owner",
                    username,
                    token,
                    expiresInDays:
                        ADMIN_SESSION_DAYS
                });
            }

            /* ADMIN ACCOUNTS */

            const snapshot =
                await db
                    .ref("admins")
                    .orderByChild(
                        "username"
                    )
                    .equalTo(username)
                    .once("value");

            if (!snapshot.exists()) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid username or password"
                });
            }

            const data =
                snapshot.val();

            let adminId = null;
            let adminAccount = null;

            for (
                const id of
                Object.keys(data)
            ) {
                if (
                    data[id].active !==
                        false &&
                    data[id].username ===
                        username
                ) {
                    adminId = id;

                    adminAccount = {
                        adminId: id,
                        ...data[id]
                    };

                    break;
                }
            }

            if (!adminAccount) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid username or password"
                });
            }

            const valid =
                verifyPassword(
                    password,
                    adminAccount.passwordHash,
                    adminAccount.passwordSalt
                );

            if (!valid) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid username or password"
                });
            }

            const token =
                createAdminSession({
                    adminId,
                    role: "ADMIN",
                    username:
                        adminAccount.username,
                    name:
                        adminAccount.name ||
                        adminAccount.username,
                    permissions:
                        adminAccount.permissions ||
                        []
                });

            await db
                .ref(
                    `admins/${adminId}`
                )
                .update({
                    lastLoginAt:
                        now()
                });

            return res.json({
                success: true,
                role: "ADMIN",
                adminId,
                name:
                    adminAccount.name ||
                    adminAccount.username,
                username:
                    adminAccount.username,
                permissions:
                    adminAccount.permissions ||
                    [],
                token,
                expiresInDays:
                    ADMIN_SESSION_DAYS
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
    }
);

app.post(
    "/api/admin/logout",
    requireAdminSession,
    (req, res) => {
        const token =
            getAdminToken(req);

        deleteAdminSession(token);

        res.json({
            success: true,
            message:
                "Logged out successfully"
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
                role:
                    req.adminSession.role,
                adminId:
                    req.adminSession.adminId ||
                    null,
                username:
                    req.adminSession.username,
                name:
                    req.adminSession.name,
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
                    .map(
                        ([
                            adminId,
                            account
                        ]) => ({
                            adminId,
                            username:
                                account.username,
                            name:
                                account.name ||
                                "",
                            role:
                                account.role ||
                                "ADMIN",
                            permissions:
                                account.permissions ||
                                [],
                            active:
                                account.active !==
                                false,
                            createdAt:
                                account.createdAt,
                            lastLoginAt:
                                account.lastLoginAt ||
                                null
                        })
                    );

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
                clean(
                    req.body.username
                );

            const name =
                clean(
                    req.body.name
                );

            const password =
                String(
                    req.body.password ||
                    ""
                );

            let permissions =
                Array.isArray(
                    req.body.permissions
                )
                    ? req.body.permissions
                    : [];

            if (
                !username ||
                !password
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Username and password are required"
                });
            }

            if (
                password.length < 6
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Password must be at least 6 characters"
                });
            }

            if (
                username ===
                ADMIN_USERNAME
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "This username belongs to owner"
                });
            }

            const existing =
                await db
                    .ref("admins")
                    .orderByChild(
                        "username"
                    )
                    .equalTo(username)
                    .once("value");

            if (
                existing.exists()
            ) {
                return res.status(409).json({
                    success: false,
                    message:
                        "Username already exists"
                });
            }

            const adminId =
                await generateUniqueId(
                    "admins",
                    10
                );

            const passwordData =
                createPasswordHash(
                    password
                );

            const allowedPermissions = [
                "users",
                "rooms",
                "agencies",
                "ads",
                "banUsers",
                "transactions",
                "shipping",
                "reports"
            ];

            permissions =
                permissions.filter(
                    p =>
                        allowedPermissions.includes(
                            p
                        )
                );

            const account = {
                adminId,
                username,
                name:
                    name || username,
                role: "ADMIN",
                passwordHash:
                    passwordData.hash,
                passwordSalt:
                    passwordData.salt,
                permissions,
                active: true,
                createdAt: now(),
                createdBy:
                    req.adminSession.username
            };

            await db
                .ref(
                    `admins/${adminId}`
                )
                .set(account);

            res.json({
                success: true,
                message:
                    "Admin created successfully",
                admin: {
                    adminId,
                    username,
                    name:
                        name || username,
                    role: "ADMIN",
                    permissions,
                    active: true,
                    createdAt:
                        account.createdAt
                }
            });
        } catch (error) {
            console.error(error);

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
            const adminId =
                req.params.adminId;

            const ref =
                db.ref(
                    `admins/${adminId}`
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
                req.body.name !==
                undefined
            ) {
                updates.name =
                    clean(
                        req.body.name
                    );
            }

            if (
                req.body.active !==
                undefined
            ) {
                updates.active =
                    Boolean(
                        req.body.active
                    );
            }

            if (
                Array.isArray(
                    req.body.permissions
                )
            ) {
                const allowed = [
                    "users",
                    "rooms",
                    "agencies",
                    "ads",
                    "banUsers",
                    "transactions",
                    "shipping",
                    "reports"
                ];

                updates.permissions =
                    req.body.permissions.filter(
                        p =>
                            allowed.includes(
                                p
                            )
                    );
            }

            if (
                req.body.password !==
                undefined
            ) {
                const password =
                    String(
                        req.body.password
                    );

                if (
                    password.length < 6
                ) {
                    return res.status(400).json({
                        success: false,
                        message:
                            "Password must be at least 6 characters"
                    });
                }

                const hashData =
                    createPasswordHash(
                        password
                    );

                updates.passwordHash =
                    hashData.hash;

                updates.passwordSalt =
                    hashData.salt;
            }

            updates.updatedAt =
                now();

            await ref.update(
                updates
            );

            const updated =
                await ref.once(
                    "value"
                );

            const account =
                updated.val();

            res.json({
                success: true,
                admin: {
                    adminId,
                    username:
                        account.username,
                    name:
                        account.name,
                    role:
                        account.role,
                    permissions:
                        account.permissions ||
                        [],
                    active:
                        account.active !==
                        false,
                    createdAt:
                        account.createdAt,
                    updatedAt:
                        account.updatedAt
                }
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
            const adminId =
                req.params.adminId;

            const ref =
                db.ref(
                    `admins/${adminId}`
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

            await ref.remove();

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

app.post(
    "/api/users",
    async (req, res) => {
        try {
            const firebaseUid =
                clean(
                    req.body.firebaseUid
                );

            const name =
                clean(
                    req.body.name
                );

            const email =
                clean(
                    req.body.email
                );

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
                    user: existing
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
                name,
                email,
                coins: 0,
                agencyId: null,
                role,
                banned: false,
                createdAt: now()
            };

            await db
                .ref(
                    `users/${userId}`
                )
                .set(userData);

            res.json({
                success: true,
                message:
                    "User created successfully",
                userId,
                user: userData
            });
        } catch (error) {
            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Failed to create user"
            });
        }
    }
);

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
                req.user.role !==
                    "OWNER" &&
                req.user.role !==
                    "ADMIN"
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
                    clean(
                        req.body.name
                    );
            }

            if (
                req.body.email !==
                undefined
            ) {
                updates.email =
                    clean(
                        req.body.email
                    );
            }

            if (
                !Object.keys(
                    updates
                ).length
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "No valid fields"
                });
            }

            updates.updatedAt =
                now();

            await ref.update(
                updates
            );

            const updated =
                await ref.once(
                    "value"
                );

            res.json({
                success: true,
                user: {
                    userId:
                        req.params.userId,
                    ...updated.val()
                }
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
   ADMIN USERS
========================================================= */

app.get(
    "/api/admin/users",
    requireAdminSession,
    requireAdminPermission(
        "users"
    ),
    async (req, res) => {
        try {
            const snapshot =
                await db
                    .ref("users")
                    .once("value");

            const data =
                snapshot.val() || {};

            const users =
                Object.entries(data)
                    .map(
                        ([
                            userId,
                            user
                        ]) => ({
                            userId,
                            ...user
                        })
                    );

            res.json({
                success: true,
                count:
                    users.length,
                users
            });
        } catch (error) {
            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Failed to load users"
            });
        }
    }
);

app.get(
    "/api/admin/users/:userId",
    requireAdminSession,
    requireAdminPermission(
        "users"
    ),
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
                    "Failed to load user"
            });
        }
    }
);

/* =========================================================
   ROOMS
========================================================= */

app.get(
    "/api/rooms",
    async (req, res) => {
        try {
            const snapshot =
                await db
                    .ref("rooms")
                    .once("value");

            const data =
                snapshot.val() || {};

            const rooms =
                Object.entries(data)
                    .map(
                        ([
                            roomId,
                            room
                        ]) => ({
                            roomId,
                            ...room
                        })
                    )
                    .filter(
                        room =>
                            room.deleted !==
                                true &&
                            room.active !==
                                false
                    )
                    .sort(
                        (a, b) =>
                            Number(
                                b.activityCoins ||
                                b.coins ||
                                0
                            ) -
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
    }
);

app.post(
    "/api/rooms",
    requireAuth,
    async (req, res) => {
        try {
            const name =
                clean(
                    req.body.name
                );

            const description =
                clean(
                    req.body.description
                );

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
                active: true,
                deleted: false,
                createdAt: now()
            };

            await db
                .ref(
                    `rooms/${roomId}`
                )
                .set(room);

            await db
                .ref(
                    `rooms/${roomId}/members/${req.user.userId}`
                )
                .set({
                    userId:
                        req.user.userId,
                    joinedAt:
                        now(),
                    owner: true
                });

            await db
                .ref(
                    `rooms/${roomId}/membersCount`
                )
                .set(1);

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

/* =========================================================
   ROOM JOIN
========================================================= */

app.post(
    "/api/rooms/:roomId/join",
    requireAuth,
    async (req, res) => {
        try {
            const roomId =
                req.params.roomId;

            const roomRef =
                db.ref(
                    `rooms/${roomId}`
                );

            const roomSnapshot =
                await roomRef.once(
                    "value"
                );

            if (
                !roomSnapshot.exists()
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Room not found"
                });
            }

            const room =
                roomSnapshot.val();

            if (
                room.deleted === true ||
                room.active === false
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Room is not active"
                });
            }

            const memberRef =
                db.ref(
                    `rooms/${roomId}/members/${req.user.userId}`
                );

            const member =
                await memberRef.once(
                    "value"
                );

            if (member.exists()) {
                return res.json({
                    success: true,
                    joined: true,
                    message:
                        "Already a member"
                });
            }

            await memberRef.set({
                userId:
                    req.user.userId,
                joinedAt:
                    now()
            });

            await roomRef.transaction(
                value => {
                    if (!value) {
                        return value;
                    }

                    value.membersCount =
                        Number(
                            value.membersCount ||
                            0
                        ) + 1;

                    return value;
                }
            );

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
            const roomId =
                req.params.roomId;

            const memberRef =
                db.ref(
                    `rooms/${roomId}/members/${req.user.userId}`
                );

            const member =
                await memberRef.once(
                    "value"
                );

            if (!member.exists()) {
                return res.json({
                    success: true,
                    joined: false
                });
            }

            await memberRef.remove();

            await db
                .ref(
                    `rooms/${roomId}`
                )
                .transaction(
                    room => {
                        if (!room) {
                            return room;
                        }

                        room.membersCount =
                            Math.max(
                                0,
                                Number(
                                    room.membersCount ||
                                    0
                                ) - 1
                            );

                        return room;
                    }
                );

            res.json({
                success: true,
                joined: false
            });
        } catch (error) {
            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Failed to leave room"
            });
        }
    }
);

/* =========================================================
   ROOM MEMBERS
========================================================= */

app.get(
    "/api/rooms/:roomId/members",
    requireAuth,
    async (req, res) => {
        try {
            const snapshot =
                await db
                    .ref(
                        `rooms/${req.params.roomId}/members`
                    )
                    .once("value");

            const data =
                snapshot.val() || {};

            const members = [];

            for (
                const [
                    userId,
                    member
                ] of Object.entries(data)
            ) {
                const user =
                    await getUser(
                        userId
                    );

                if (user) {
                    members.push({
                        userId,
                        name:
                            user.name ||
                            "",
                        member,
                        banned:
                            user.banned ===
                            true
                    });
                }
            }

            res.json({
                success: true,
                members
            });
        } catch (error) {
            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Failed to load room members"
            });
        }
    }
);

/* =========================================================
   ROOM FOLLOW
========================================================= */

app.post(
    "/api/rooms/:roomId/follow",
    requireAuth,
    async (req, res) => {
        try {
            const roomId =
                req.params.roomId;

            const roomSnapshot =
                await db
                    .ref(
                        `rooms/${roomId}`
                    )
                    .once("value");

            if (
                !roomSnapshot.exists()
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Room not found"
                });
            }

            const followRef =
                db.ref(
                    `users/${req.user.userId}/followingRooms/${roomId}`
                );

            const current =
                await followRef.once(
                    "value"
                );

            if (current.exists()) {
                await followRef.remove();

                return res.json({
                    success: true,
                    following: false
                });
            }

            await followRef.set({
                roomId,
                followedAt:
                    now()
            });

            res.json({
                success: true,
                following: true
            });
        } catch (error) {
            console.error(error);

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
                const roomId of
                Object.keys(following)
            ) {
                const roomSnapshot =
                    await db
                        .ref(
                            `rooms/${roomId}`
                        )
                        .once("value");

                if (
                    roomSnapshot.exists()
                ) {
                    rooms.push({
                        roomId,
                        ...roomSnapshot.val(),
                        isFollowing:
                            true
                    });
                }
            }

            res.json({
                success: true,
                rooms
            });
        } catch (error) {
            console.error(error);

            res.status(500).json({
                success: false,
                message:
                    "Failed to load following rooms"
            });
        }
    }
);

/* =========================================================
   ADMIN ROOM MANAGEMENT
========================================================= */

app.get(
    "/api/admin/rooms",
    requireAdminSession,
    requireAdminPermission(
        "rooms"
    ),
    async (req, res) => {
        try {
            const snapshot =
                await db
                    .ref("rooms")
                    .once("value");

            const data =
                snapshot.val() || {};

            const rooms =
                Object.entries(data)
                    .map(
                        ([
                            roomId,
                            room
                        ]) => ({
                            roomId,
                            ...room
                        })
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
    }
);

app.patch(
    "/api/admin/rooms/:roomId",
    requireAdminSession,
    requireAdminPermission(
        "rooms"
    ),
    async (req, res) => {
        try {
            const ref =
                db.ref(
                    `rooms/${req.params.roomId}`
                );

            const snapshot =
                await ref.once(
                    "value"
                );

            if (!snapshot.exists()) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Room not found"
                });
            }

            const updates = {};

            if (
                req.body.name !==
                undefined
            ) {
                updates.name =
                    clean(
                        req.body.name
                    );
            }

            if (
                req.body.descr