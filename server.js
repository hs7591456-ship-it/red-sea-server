hereconst express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: "2mb" }));

const serviceAccount = require("/etc/secrets/serviceAccountKey.json");

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://red-sea-8db76-default-rtdb.firebaseio.com"
});

const db = admin.database();

const OWNER_FIREBASE_UID = process.env.OWNER_FIREBASE_UID || "";

function now() {
    return new Date().toISOString();
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

        const snapshot = await db
            .ref(`${path}/${id}`)
            .once("value");

        if (!snapshot.exists()) {
            return id;
        }
    }
}

function clean(value) {
    return String(value ?? "").trim();
}

async function getUserByFirebaseUid(firebaseUid) {
    const snapshot = await db
        .ref("users")
        .orderByChild("firebaseUid")
        .equalTo(firebaseUid)
        .once("value");

    if (!snapshot.exists()) {
        return null;
    }

    const users = snapshot.val();
    const userId = Object.keys(users)[0];

    return {
        userId,
        ...users[userId]
    };
}

async function requireAuth(req, res, next) {
    try {
        const header = req.headers.authorization || "";

        if (!header.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const token = header.substring(7);

        const decoded = await admin
            .auth()
            .verifyIdToken(token);

        const user = await getUserByFirebaseUid(decoded.uid);

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

        console.error("Auth error:", error.message);

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
            req.firebaseUser.uid !== OWNER_FIREBASE_UID
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

        await db.ref("server/status").set({
            online: true,
            updatedAt: now()
        });

        res.json({
            success: true,
            message: "Red Sea API + Firebase are working",
            database: "connected",
            timestamp: now()
        });

    } catch (error) {

        console.error("Firebase error:", error);

        res.status(500).json({
            success: false,
            message: "Firebase connection failed"
        });
    }

});


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
                message: "firebaseUid is required"
            });

        }

        const existing =
            await getUserByFirebaseUid(firebaseUid);

        if (existing) {

            return res.json({
                success: true,
                message: "User already exists",
                userId: existing.userId,
                user: existing
            });

        }

        const userId =
            await generateUniqueId("users", 8);

        const role =
            OWNER_FIREBASE_UID &&
            firebaseUid === OWNER_FIREBASE_UID
                ? "OWNER"
                : "USER";

        const userData = {

            userId,

            firebaseUid,

            name: clean(name),

            email: clean(email),

            coins: 0,

            agencyId: null,

            role,

            banned: false,

            createdAt: now()
        };

        await db
            .ref(`users/${userId}`)
            .set(userData);

        res.json({

            success: true,

            message: "User created successfully",

            userId,

            user: userData
        });

    } catch (error) {

        console.error("Create user error:", error);

        res.status(500).json({

            success: false,

            message: "Failed to create user"
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
                    message: "User not found"
                });

            }

            res.json({
                success: true,
                user
            });

        } catch (error) {

            console.error(
                "Get Firebase user error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Failed to get user"
            });
        }

    }
);


app.get(
    "/api/users/:userId",
    requireAuth,
    async (req, res) => {

        try {

            const snapshot =
                await db
                    .ref(`users/${req.params.userId}`)
                    .once("value");

            if (!snapshot.exists()) {

                return res.status(404).json({
                    success: false,
                    message: "User not found"
                });

            }

            res.json({

                success: true,

                user: {
                    userId: req.params.userId,
                    ...snapshot.val()
                }

            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message: "Failed to get user"
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
                req.user.userId !== req.params.userId &&
                req.user.role !== "OWNER" &&
                req.user.role !== "ADMIN"
            ) {

                return res.status(403).json({
                    success: false,
                    message: "Permission denied"
                });

            }

            const ref =
                db.ref(`users/${req.params.userId}`);

            const snapshot =
                await ref.once("value");

            if (!snapshot.exists()) {

                return res.status(404).json({
                    success: false,
                    message: "User not found"
                });

            }

            const updates = {};

            if (req.body.name !== undefined) {
                updates.name = clean(req.body.name);
            }

            if (!Object.keys(updates).length) {

                return res.status(400).json({
                    success: false,
                    message: "No valid fields to update"
                });

            }

            updates.updatedAt = now();

            await ref.update(updates);

            const updated =
                await ref.once("value");

            res.json({

                success: true,

                user: {
                    userId: req.params.userId,
                    ...updated.val()
                }

            });

        } catch (error) {

            console.error(
                "Update user error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Failed to update user"
            });
        }

    }
);


/* =========================================================
   ROOMS
========================================================= */

app.get("/api/rooms", async (req, res) => {

    try {

        const snapshot =
            await db.ref("rooms").once("value");

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

        console.error(
            "Rooms error:",
            error
        );

        res.status(500).json({
            success: false,
            message: "Failed to load rooms"
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
                    message: "Room name is required"
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
                    req.user.agencyId || null,

                membersCount: 0,

                activityCoins: 0,

                active: true,

                deleted: false,

                createdAt: now()
            };

            await db
                .ref(`rooms/${roomId}`)
                .set(room);

            res.json({
                success: true,
                room
            });

        } catch (error) {

            console.error(
                "Create room error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Failed to create room"
            });
        }

    }
);


/* =========================================================
   FOLLOW ROOMS
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
                    .ref(`rooms/${roomId}`)
                    .once("value");

            if (!roomSnapshot.exists()) {

                return res.status(404).json({
                    success: false,
                    message: "Room not found"
                });

            }

            const followRef =
                db.ref(
                    `users/${req.user.userId}/followingRooms/${roomId}`
                );

            const current =
                await followRef.once("value");

            if (current.exists()) {

                await followRef.remove();

                return res.json({
                    success: true,
                    following: false
                });

            }

            await followRef.set({

                roomId,

                followedAt: now()

            });

            res.json({

                success: true,

                following: true
            });

        } catch (error) {

            console.error(
                "Follow error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Failed to update follow"
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

            const roomIds =
                Object.keys(following);

            const rooms = [];

            for (const roomId of roomIds) {

                const roomSnapshot =
                    await db
                        .ref(`rooms/${roomId}`)
                        .once("value");

                if (roomSnapshot.exists()) {

                    rooms.push({

                        roomId,

                        ...roomSnapshot.val(),

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
                message: "Failed to load following rooms"
            });
        }

    }
);


/* =========================================================
   NORMAL AGENCIES
========================================================= */

app.get(
    "/api/agencies/top",
    async (req, res) => {

        try {

            const limit =
                Math.min(
                    Math.max(
                        Number(req.query.limit || 4),
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

                    .map(([agencyId, agency]) => ({
                        agencyId,
                        ...agency
                    }))

                    .filter(agency =>
                        agency.deleted !== true &&
                        agency.active !== false &&
                        agency.type !== "SHIPPING"
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
                message: "Failed to load agencies"
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
                    message: "Agency name is required"
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

                active: true,

                deleted: false,

                createdAt: now()
            };

            await db
                .ref(`agencies/${agencyId}`)
                .set(agency);

            res.json({

                success: true,

                agency
            });

        } catch (error) {

            console.error(
                "Create agency error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Failed to create agency"
            });
        }

    }
);


/* =========================================================
   SHIPPING AGENCIES
========================================================= */

app.get(
    "/api/shipping-agencies",
    async (req, res) => {

        try {

            const snapshot =
                await db
                    .ref("agencies")
                    .once("value");

            const data =
                snapshot.val() || {};

            const agencies =
                Object.entries(data)

                    .map(([agencyId, agency]) => ({
                        agencyId,
                        ...agency
                    }))

                    .filter(agency =>
                        agency.type === "SHIPPING" &&
                        agency.deleted !== true &&
                        agency.active !== false
                    );

            res.json({

                success: true,

                agencies
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                message: "Failed to load shipping agencies"
            });
        }

    }
);


app.post(
    "/api/shipping-agencies",
    requireAuth,
    requireOwner,
    async (req, res) => {

        try {

            const name =
                clean(req.body.name);

            const userId =
                clean(req.body.userId);

            if (!name || !userId) {

                return res.status(400).json({
                    success: false,
                    message:
                        "name and userId are required"
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
                        "Shipping agency user not found"
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

                type: "SHIPPING",

                ownerId: userId,

                balance: 0,

                activityCoins: 0,

                active: true,

                deleted: false,

                createdAt: now()
            };

            await db
                .ref(`agencies/${agencyId}`)
                .set(agency);

            await userRef.update({

                agencyId,

                role: "SHIPPING_AGENT",

                updatedAt: now()
            });

            res.json({

                success: true,

                agency
            });

        } catch (error) {

            console.error(
                "Create shipping agency error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Failed to create shipping agency"
            });
        }

    }
);


/* =========================================================
   SHIPPING
========================================================= */

app.post(
    "/api/shipping/charge",
    requireAuth,
    async (req, res) => {

        try {

            if (
                req.user.role !== "SHIPPING_AGENT" &&
                req.user.role !== "OWNER"
            ) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Shipping permission required"
                });

            }

            const targetUserId =
                clean(req.body.targetUserId);

            const amount =
                Number(req.body.amount);

            if (!/^\d{8}$/.test(targetUserId)) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid target user ID"
                });

            }

            if (
                !Number.isInteger(amount) ||
                amount <= 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid amount"
                });

            }

            const agencyId =
                req.user.agencyId;

            if (
                !agencyId &&
                req.user.role !== "OWNER"
            ) {

                return res.status(403).json({
                    success: false,
                    message:
                        "No shipping agency assigned"
                });

            }

            const targetRef =
                db.ref(`users/${targetUserId}`);

            const targetSnapshot =
                await targetRef.once("value");

            if (!targetSnapshot.exists()) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Target user not found"
                });

            }

            const target =
                targetSnapshot.val();

            if (target.banned === true) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Target user is banned"
                });

            }

            const transactionId =
                await generateUniqueId(
                    "transactions",
                    12
                );

            if (req.user.role === "OWNER") {

                await targetRef.transaction(
                    user => {

                        if (!user) {
                            return user;
                        }

                        user.coins =
                            Number(user.coins || 0) +
                            amount;

                        user.updatedAt = now();

                        return user;
                    }
                );

            } else {

                const agencyRef =
                    db.ref(
                        `agencies/${agencyId}`
                    );

                const result =
                    await agencyRef.transaction(
                        agency => {

                            if (!agency) {
                                return;
                            }

                            const balance =
                                Number(
                                    agency.balance || 0
                                );

                            if (balance < amount) {
                                return;
                            }

                            agency.balance =
                                balance - amount;

                            agency.updatedAt =
                                now();

                            return agency;
                        }
                    );

                if (!result.committed) {

                    return res.status(400).json({
                        success: false,
                        message:
                            "Insufficient shipping balance"
                    });

                }

                await targetRef.transaction(
                    user => {

                        if (!user) {
                            return user;
                        }

                        user.coins =
                            Number(user.coins || 0) +
                            amount;

                        user.updatedAt =
                            now();

                        return user;
                    }
                );

            }

            await db
                .ref(`transactions/${transactionId}`)
                .set({

                    transactionId,

                    type: "SHIPPING",

                    shippingAgencyId:
                        agencyId || null,

                    agentUserId:
                        req.user.userId,

                    targetUserId,

                    amount,

                    createdAt: now()
                });

            res.json({

                success: true,

                message:
                    "User charged successfully",

                transactionId,

                targetUserId,

                amount
            });

        } catch (error) {

            console.error(
                "Shipping error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Shipping operation failed"
            });
        }

    }
);


/* =========================================================
   ADS
========================================================= */

app.get("/api/ads", async (req, res) => {

    try {

        const snapshot =
            await db
                .ref("ads")
                .once("value");

        const data =
            snapshot.val() || {};

        const ads =
            Object.entries(data)

                .map(([id, ad]) => ({
                    id,
                    ...ad
                }))

                .filter(ad =>
                    ad.active !== false
                )

                .sort((a, b) =>
                    Number(a.order || 0) -
                    Number(b.order || 0)
                );

        res.json({

            success: true,

            ads
        });

    } catch (error) {

        res.status(500).json({
            success: false,
            message: "Failed to load ads"
        });
    }

});


app.post(
    "/api/ads",
    requireAuth,
    requireOwner,
    async (req, res) => {

        try {

            const title =
                clean(req.body.title);

            const description =
                clean(req.body.description);

            const imageUrl =
                clean(req.body.imageUrl);

            if (!title && !imageUrl) {

                return res.status(400).json({
                    success: false,
                    message:
                        "title or imageUrl is required"
                });

            }

            const adId =
                await generateUniqueId(
                    "ads",
                    10
                );

            const ad = {

                adId,

                title,

                description,

                imageUrl,

                active: true,

                order:
                    Number(req.body.order || 0),

                createdAt: now(),

                createdBy:
                    req.user.userId
            };

            await db
                .ref(`ads/${adId}`)
                .set(ad);

            res.json({

                success: true,

                ad
            });

        } catch (error) {

            console.error(
                "Create ad error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Failed to create ad"
            });
        }

    }
);


/* =========================================================
   BAN / UNBAN
========================================================= */

app.post(
    "/api/admin/users/:userId/ban",
    requireAuth,
    requireOwnerOrAdmin,
    async (req, res) => {

        try {

            const targetRef =
                db.ref(
                    `users/${req.params.userId}`
                );

            const snapshot =
                await targetRef.once("value");

            if (!snapshot.exists()) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User not found"
                });

            }

            const target =
                snapshot.val();

            if (target.role === "OWNER") {

                return res.status(403).json({
                    success: false,
                    message:
                        "Owner cannot be banned"
                });

            }

            await targetRef.update({

                banned: true,

                bannedBy:
                    req.user.userId,

                bannedAt:
                    now(),

                banReason:
                    clean(req.body.reason)
            });

            res.json({

                success: true,

                message:
                    "User banned successfully"
            });

        } catch (error) {

            console.error(
                "Ban error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Failed to ban user"
            });
        }

    }
);


app.post(
    "/api/admin/users/:userId/unban",
    requireAuth,
    requireOwnerOrAdmin,
    async (req, res) => {

        try {

            const targetRef =
                db.ref(
                    `users/${req.params.userId}`
                );

            const snapshot =
                await targetRef.once("value");

            if (!snapshot.exists()) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User not found"
                });

            }

            await targetRef.update({

                banned: false,

                updatedAt:
                    now()
            });

            res.json({

                success: true,

                message:
                    "User unbanned successfully"
            });

        } catch (error) {

            console.error(
                "Unban error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Failed to unban user"
            });
        }

    }
);


/* =========================================================
   OWNER -> CREATE ADMIN
========================================================= */

app.post(
    "/api/owner/admins",
    requireAuth,
    requireOwner,
    async (req, res) => {

        try {

            const userId =
                clean(req.body.userId);

            if (!userId) {

                return res.status(400).json({
                    success: false,
                    message:
                        "userId is required"
                });

            }

            const ref =
                db.ref(`users/${userId}`);

            const snapshot =
                await ref.once("value");

            if (!snapshot.exists()) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User not found"
                });

            }

            const target =
                snapshot.val();

            if (target.role === "OWNER") {

                return res.status(400).json({
                    success: false,
                    message:
                        "User is already owner"
                });

            }

            await ref.update({

                role: "ADMIN",

                updatedAt:
                    now()
            });

            res.json({

                success: true,

                message:
                    "Admin assigned successfully"
            });

        } catch (error) {

            console.error(
                "Admin assignment error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Failed to assign admin"
            });
        }

    }
);


/* =========================================================
   START SERVER
========================================================= */

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `Red Sea Server running on port ${PORT}`
        );

    }
);
