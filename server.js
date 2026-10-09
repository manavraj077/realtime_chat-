const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const { randomInt } = require("crypto");

const GOOGLE_CLIENT_ID =
    "479742394396-vu6ii0k2n5naeg2ufdougd297gks5fac.apps.googleusercontent.com";

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    maxHttpBufferSize: 5e6
});

const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    throw new Error("JWT_SECRET environment variable is missing.");
}


// ===============================
// MIDDLEWARE
// ===============================

app.use(express.json({ limit: "6mb" }));
app.use(express.static("public"));


// ===============================
// MYSQL CONNECTION
// ===============================

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        ca: process.env.DB_SSL_CA,
        rejectUnauthorized: true
    }
});

db.connect((err) => {
    if (err) {
        console.error("MySQL connection failed:", err.message);
    } else {
        console.log("MySQL connected successfully!");
    }
});


// ===============================
// ONLINE USERS
// ===============================

// socket.id -> user information
const onlineUsers = {};

// ===============================
// DEVELOPMENT OTP STORAGE
// ===============================

const otpStore = new Map();


// ===============================
// REGISTER
// ===============================

app.post("/register", async (req, res) => {

    const username = (req.body.username || "").trim();
    const password = req.body.password || "";

    if (!username || !password) {
        return res.json({
            success: false,
            message: "Username and password are required."
        });
    }

    if (username.length < 3) {
        return res.json({
            success: false,
            message: "Username must contain at least 3 characters."
        });
    }

    if (password.length < 4) {
        return res.json({
            success: false,
            message: "Password must contain at least 4 characters."
        });
    }

    db.query(
        "SELECT id FROM users WHERE username = ?",
        [username],
        async (err, rows) => {

            if (err) {
                return res.json({
                    success: false,
                    message: "Database error."
                });
            }

            if (rows.length > 0) {
                return res.json({
                    success: false,
                    message: "Username already exists."
                });
            }

            const hash = await bcrypt.hash(password, 10);

            db.query(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                [username, hash],
                (err) => {

                    if (err) {
                        return res.json({
                            success: false,
                            message: "Registration failed."
                        });
                    }

                    res.json({
                        success: true,
                        message: "Account created successfully."
                    });
                }
            );
        }
    );
});


// ===============================
// LOGIN
// ===============================

app.post("/login", (req, res) => {

    const username = (req.body.username || "").trim();
    const password = req.body.password || "";

    if (!username || !password) {
        return res.json({
            success: false,
            message: "Username and password are required."
        });
    }

    db.query(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, rows) => {

            if (err) {
                return res.json({
                    success: false,
                    message: "Database error."
                });
            }

            if (rows.length === 0) {
                return res.json({
                    success: false,
                    message: "Invalid username or password."
                });
            }

            const user = rows[0];

            const passwordCorrect =
                await bcrypt.compare(password, user.password);

            if (!passwordCorrect) {
                return res.json({
                    success: false,
                    message: "Invalid username or password."
                });
            }

            const token = jwt.sign(
                {
                    id: user.id,
                    username: user.username
                },
                JWT_SECRET,
                {
                    expiresIn: "7d"
                }
            );

            res.json({
                success: true,
                token: token,
                username: user.username
            });
        }
    );
});

// ===============================
// PHONE LOGIN - SEND OTP
// DEVELOPMENT VERSION
// ===============================

app.post("/phone-send-otp", (req, res) => {

    const phone =
        String(req.body.phone || "").trim();


    // Basic phone validation

    if (!/^[0-9]{10}$/.test(phone)) {

        return res.json({
            success: false,
            message: "Enter a valid 10-digit phone number."
        });

    }


    // Generate 6-digit OTP

    const otp =
        String(
            randomInt(
                100000,
                1000000
            )
        );


    // OTP expires after 5 minutes

    const expiresAt =
        Date.now() +
        5 * 60 * 1000;


    // Store OTP temporarily

    otpStore.set(
        phone,
        {
            otp: otp,
            expiresAt: expiresAt
        }
    );


    // DEVELOPMENT ONLY
    // OTP appears in Command Prompt

    console.log("");
    console.log("===============================");
    console.log("PHONE OTP");
    console.log("===============================");
    console.log("Phone:", phone);
    console.log("OTP:", otp);
    console.log("Expires in: 5 minutes");
    console.log("===============================");
    console.log("");


    res.json({
        success: true,
        message:
            "OTP generated successfully."
    });

});

// ===============================
// PHONE LOGIN - VERIFY OTP
// DEVELOPMENT VERSION
// ===============================

app.post("/phone-verify-otp", (req, res) => {

    const phone =
        String(req.body.phone || "").trim();

    const otp =
        String(req.body.otp || "").trim();


    // Check input

    if (
        !/^[0-9]{10}$/.test(phone) ||
        !/^[0-9]{6}$/.test(otp)
    ) {

        return res.json({
            success: false,
            message:
                "Invalid phone number or OTP."
        });

    }


    // Get stored OTP

    const stored =
        otpStore.get(phone);


    if (!stored) {

        return res.json({
            success: false,
            message:
                "OTP not found. Please request a new OTP."
        });

    }


    // Check expiration

    if (
        Date.now() >
        stored.expiresAt
    ) {

        otpStore.delete(phone);

        return res.json({
            success: false,
            message:
                "OTP expired. Please request a new OTP."
        });

    }


    // Check OTP

    if (
        stored.otp !== otp
    ) {

        return res.json({
            success: false,
            message:
                "Incorrect OTP."
        });

    }


    // OTP is correct

    otpStore.delete(phone);


    // ===============================
    // CHECK IF USER EXISTS
    // ===============================

    db.query(
        "SELECT * FROM users WHERE phone = ?",
        [phone],
        (err, rows) => {

            if (err) {

                console.error(
                    "Phone login database error:",
                    err
                );

                return res.status(500).json({
                    success: false,
                    message:
                        "Database error."
                });

            }


            // ===============================
            // EXISTING USER
            // ===============================

            if (rows.length > 0) {

                const user =
                    rows[0];


                const token =
                    jwt.sign(
                        {
                            id: user.id,
                            username: user.username
                        },
                        JWT_SECRET,
                        {
                            expiresIn: "7d"
                        }
                    );


                return res.json({

                    success: true,

                    token: token,

                    username:
                        user.username,

                    userId:
                        user.id

                });

            }


            // ===============================
            // NEW USER
            // ===============================

            const username =
                "User_" +
                phone.slice(-4) +
                "_" +
                Date.now();


            // Create a password hash
            // because your users table
            // currently expects a password.

            bcrypt.hash(
                "PHONE_LOGIN_ACCOUNT",
                10,
                (hashErr, hash) => {

                    if (hashErr) {

                        console.error(
                            "Password hash error:",
                            hashErr
                        );

                        return res.status(500).json({
                            success: false,
                            message:
                                "Could not create account."
                        });

                    }


                    // ===============================
                    // CREATE USER
                    // ===============================

                    db.query(
                        `INSERT INTO users
                        (
                            username,
                            password,
                            phone
                        )
                        VALUES (?, ?, ?)`,
                        [
                            username,
                            hash,
                            phone
                        ],
                        (insertErr, result) => {

                            if (insertErr) {

                                console.error(
                                    "Create phone user error:",
                                    insertErr
                                );

                                return res.status(500).json({
                                    success: false,
                                    message:
                                        "Could not create account."
                                });

                            }


                            // ===============================
                            // CREATE JWT
                            // ===============================

                            const token =
                                jwt.sign(
                                    {
                                        id:
                                            result.insertId,

                                        username:
                                            username
                                    },
                                    JWT_SECRET,
                                    {
                                        expiresIn: "7d"
                                    }
                                );


                            res.json({

                                success: true,

                                token:
                                    token,

                                username:
                                    username,

                                userId:
                                    result.insertId

                            });

                        }
                    );

                }
            );

        }
    );

});


// ===============================
// GOOGLE LOGIN
// ===============================

app.post("/google-login", async (req, res) => {

    try {

        const { credential } = req.body;

        if (!credential) {
            return res.status(400).json({
                success: false,
                message: "Google credential missing"
            });
        }

        const ticket = await googleClient.verifyIdToken({
            idToken: credential,
            audience: GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();

        const googleId = payload.sub;
        const email = payload.email;

        const name =
            payload.name ||
            email.split("@")[0];

        // Check if Google account already exists
        db.query(
            "SELECT * FROM users WHERE google_id = ?",
            [googleId],
            (err, rows) => {

                if (err) {
                    return res.status(500).json({
                        success: false,
                        message: "Database error"
                    });
                }

                // Existing Google user
                if (rows.length > 0) {

                    const user = rows[0];

                    const token = jwt.sign(
                        {
                            id: user.id,
                            username: user.username
                        },
                        JWT_SECRET,
                        {
                            expiresIn: "7d"
                        }
                    );

                    return res.json({
                        success: true,
                        token: token,
                        username: user.username
                    });
                }


                // Create username
                let username = name
                    .replace(/\s+/g, "_")
                    .replace(/[^\w.-]/g, "");

                if (!username) {
                    username = "GoogleUser";
                }


                // Check username
                db.query(
                    "SELECT username FROM users WHERE username = ?",
                    [username],
                    (err, existing) => {

                        if (err) {
                            return res.status(500).json({
                                success: false,
                                message: "Database error"
                            });
                        }

                        if (existing.length > 0) {
                            username =
                                username + "_" + Date.now();
                        }


                        // Create user
                        db.query(
                            `INSERT INTO users
                            (username, password, google_id, email)
                            VALUES (?, ?, ?, ?)`,
                            [
                                username,
                                "GOOGLE_LOGIN",
                                googleId,
                                email
                            ],
                            (err, result) => {

                                if (err) {
                                    return res.status(500).json({
                                        success: false,
                                        message:
                                            "Could not create account"
                                    });
                                }

                                const token = jwt.sign(
                                    {
                                        id: result.insertId,
                                        username: username
                                    },
                                    JWT_SECRET,
                                    {
                                        expiresIn: "7d"
                                    }
                                );

                                res.json({
                                    success: true,
                                    token: token,
                                    username: username
                                });
                            }
                        );
                    }
                );
            }
        );

    } catch (error) {

        console.error(
            "Google login error:",
            error
        );

        res.status(401).json({
            success: false,
            message: "Google login failed"
        });
    }
});


// ==========================================
// CHANGE USERNAME
// ==========================================

app.post("/change-username", (req, res) => {

    const token =
        (req.headers.authorization || "")
            .split(" ")[1];

    if (!token) {
        return res.json({
            success: false,
            message: "Authentication required."
        });
    }

    let decoded;

    try {

        decoded = jwt.verify(
            token,
            JWT_SECRET
        );

    } catch (error) {

        return res.json({
            success: false,
            message: "Invalid or expired login."
        });
    }


    const newUsername =
        String(req.body.username || "")
            .trim();


    // Username validation
    if (
        newUsername.length < 3 ||
        newUsername.length > 20
    ) {

        return res.json({
            success: false,
            message:
                "Username must be 3 to 20 characters."
        });
    }


    // Allow letters, numbers, underscore and dot
    if (!/^[a-zA-Z0-9_.]+$/.test(newUsername)) {

        return res.json({
            success: false,
            message:
                "Only letters, numbers, underscore and dot are allowed."
        });
    }


    // Check if username already exists
    db.query(
        "SELECT id FROM users WHERE username = ? AND id != ?",
        [
            newUsername,
            decoded.id
        ],
        (err, rows) => {

            if (err) {

                console.error(
                    "Username check error:",
                    err
                );

                return res.json({
                    success: false,
                    message: "Database error."
                });
            }


            if (rows.length > 0) {

                return res.json({
                    success: false,
                    message:
                        "This username is already taken."
                });
            }


            // Update username
            db.query(
                "UPDATE users SET username = ? WHERE id = ?",
                [
                    newUsername,
                    decoded.id
                ],
                (updateErr) => {

                    if (updateErr) {

                        console.error(
                            "Username update error:",
                            updateErr
                        );

                        return res.json({
                            success: false,
                            message:
                                "Could not update username."
                        });
                    }

                    // Update everyone else's user list
                    sendUserList();


                    // Create new JWT
                    const newToken =
                        jwt.sign(
                            {
                                id: decoded.id,
                                username: newUsername
                            },
                            JWT_SECRET,
                            {
                                expiresIn: "7d"
                            }
                        );


                    res.json({
                        success: true,
                        message:
                            "Username changed successfully.",
                        token: newToken,
                        username: newUsername
                    });

                }
            );

        }
    );

});


// ===============================
// VERIFY LOGIN
// ===============================

app.get("/verify", (req, res) => {

    const token =
        (req.headers.authorization || "")
            .split(" ")[1];

    if (!token) {
        return res.json({
            success: false
        });
    }

    try {

        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );

        res.json({
            success: true,
            username: decoded.username,
            userId: decoded.id
        });

    } catch (error) {

        res.json({
            success: false
        });

    }
});

// ==========================================
// PROFILE PICTURE - GET
// ==========================================

app.get("/profile-picture", (req, res) => {

    const token =
        (req.headers.authorization || "")
            .split(" ")[1];

    if (!token) {
        return res.json({
            success: false,
            message: "Authentication required."
        });
    }

    let decoded;

    try {

        decoded = jwt.verify(
            token,
            JWT_SECRET
        );

    } catch (error) {

        return res.json({
            success: false,
            message: "Invalid or expired login."
        });

    }

    db.query(
        "SELECT profile_picture FROM users WHERE id = ?",
        [decoded.id],
        (err, rows) => {

            if (err) {

                console.error(
                    "Profile picture fetch error:",
                    err
                );

                return res.json({
                    success: false,
                    message: "Database error."
                });

            }

            if (rows.length === 0) {

                return res.json({
                    success: false,
                    message: "User not found."
                });

            }

            res.json({
                success: true,
                profilePicture:
                    rows[0].profile_picture || null
            });

        }
    );

});


// ==========================================
// PROFILE PICTURE - UPLOAD
// ==========================================

app.post("/profile-picture", (req, res) => {

    const token =
        (req.headers.authorization || "")
            .split(" ")[1];

    if (!token) {

        return res.json({
            success: false,
            message: "Authentication required."
        });

    }

    let decoded;

    try {

        decoded = jwt.verify(
            token,
            JWT_SECRET
        );

    } catch (error) {

        return res.json({
            success: false,
            message: "Invalid or expired login."
        });

    }


    const profilePicture =
        req.body.profilePicture;


    // Check if image was provided

    if (
        typeof profilePicture !== "string" ||
        !profilePicture
    ) {

        return res.json({
            success: false,
            message: "No profile picture selected."
        });

    }


    // Allow only JPEG, PNG and WEBP

    const allowedTypes =
        /^data:image\/(jpeg|png|webp);base64,/i;

    if (!allowedTypes.test(profilePicture)) {

        return res.json({
            success: false,
            message:
                "Only JPG, PNG and WEBP images are allowed."
        });

    }


    // Limit Base64 image size
    // Approximately 2 MB original image

    if (
        profilePicture.length >
        3 * 1024 * 1024
    ) {

        return res.json({
            success: false,
            message:
                "Profile picture is too large. Maximum size is 2 MB."
        });

    }


    // Save profile picture

    db.query(
        `UPDATE users
         SET profile_picture = ?
         WHERE id = ?`,
        [
            profilePicture,
            decoded.id
        ],
        (err) => {

            if (err) {

                console.error(
                    "Profile picture update error:",
                    err
                );

                return res.json({
                    success: false,
                    message:
                        "Could not save profile picture."
                });

            }


            res.json({
                success: true,
                message:
                    "Profile picture updated successfully.",
                profilePicture:
                    profilePicture
            });

        }
    );

});


// ===============================
// SOCKET.IO LOGIN
// ===============================

io.use((socket, next) => {

    try {

        const decoded =
            jwt.verify(
                socket.handshake.auth.token,
                JWT_SECRET
            );

        socket.userId = decoded.id;
        socket.username = decoded.username;

        next();

    } catch (error) {

        next(
            new Error("Invalid authentication")
        );
    }
});


// ===============================
// SEND USER LIST
// ===============================

function sendUserList() {

    db.query(
        "SELECT id, username, profile_picture FROM users ORDER BY username ASC",
        (err, users) => {

            if (err) {
                console.error(
                    "User list error:",
                    err
                );
                return;
            }

            const onlineIds =
                new Set(
                    Object.values(onlineUsers)
                        .map(user =>
                            Number(user.userId)
                        )
                );

            const userList =
                users.map(user => ({
                    id: user.id,
                    username: user.username,

                    profile_picture:
                        user.profile_picture || null,

                    online:
                        onlineIds.has(
                            Number(user.id)
                        )
                }));


            io.emit(
                "user list",
                userList
            );


            io.emit(
                "online users",
                Object.values(
                    onlineUsers
                ).map(user =>
                    user.username
                )
            );
        }
    );
}


// ===============================
// SEND CHAT LIST
// ===============================

function sendChatList(userId) {

    const query = `
        SELECT
            u.id,
            u.username,
            u.profile_picture,

            (
                SELECT
                    CASE
                        WHEN m.message_type = 'image'
                        THEN '📷 Photo'
                        ELSE m.message
                    END
                FROM messages m
                WHERE
                    (m.sender_id = ? AND m.receiver_id = u.id)
                    OR
                    (m.sender_id = u.id AND m.receiver_id = ?)
                ORDER BY m.id DESC
                LIMIT 1
            ) AS last_message,

            (
                SELECT m.created_at
                FROM messages m
                WHERE
                    (m.sender_id = ? AND m.receiver_id = u.id)
                    OR
                    (m.sender_id = u.id AND m.receiver_id = ?)
                ORDER BY m.id DESC
                LIMIT 1
            ) AS last_message_time,

            (
                SELECT COUNT(*)
                FROM messages m
                WHERE
                    m.sender_id = u.id
                    AND m.receiver_id = ?
                    AND m.status != 'read'
            ) AS unread_count

        FROM users u

        WHERE u.id != ?

        ORDER BY
            last_message_time IS NULL ASC,
            last_message_time DESC,
            u.username ASC
    `;

    db.query(
        query,
        [
            userId,
            userId,
            userId,
            userId,
            userId,
            userId
        ],
        (err, chats) => {

            if (err) {

                console.error(
                    "Chat list error:",
                    err
                );

                return;
            }

            const onlineIds =
                new Set(
                    Object.values(onlineUsers)
                        .map(
                            user =>
                                Number(user.userId)
                        )
                );

            const chatList =
                chats.map(chat => ({

                    id: chat.id,

                    username:
                        chat.username,
                    
                    profile_picture:
                        chat.profile_picture || null,

                    lastMessage:
                        chat.last_message ||
                        "",

                    lastMessageTime:
                        chat.last_message_time,

                    unreadCount:
                        Number(
                            chat.unread_count || 0
                        ),

                    online:
                        onlineIds.has(
                            Number(chat.id)
                        )

                }));


            emitToUser(
                userId,
                "chat list",
                chatList
            );

        }
    );
}

// ===============================
// SEND EVENT TO SPECIFIC USER
// ===============================

function emitToUser(
    userId,
    event,
    data
) {

    Object.entries(
        onlineUsers
    ).forEach(
        ([socketId, user]) => {

            if (
                Number(user.userId) ===
                Number(userId)
            ) {

                io.to(socketId)
                    .emit(
                        event,
                        data
                    );
            }
        }
    );
}


// ===============================
// SOCKET CONNECTION
// ===============================

io.on("connection", (socket) => {

    console.log(
        "CONNECTED:",
        socket.username
    );


        onlineUsers[socket.id] = {
            userId: socket.userId,
            username: socket.username
        };

        sendUserList();
        sendChatList(socket.userId);


    // Request user list
    socket.on(
    "request user list",
    () => {

        sendUserList();

        sendChatList(
            socket.userId
        );

    }
);


    // ===============================
    // LOAD PRIVATE CONVERSATION
    // ===============================

    socket.on(
        "load conversation",
        (otherUserId) => {

        console.log(
            "LOAD CONVERSATION USER ID:",
            otherUserId
        );

            const me =
                Number(socket.userId);

            const other =
                Number(otherUserId);


            if (
                !Number.isInteger(other) ||
                other <= 0 ||
                other === me
            ) {

                socket.emit(
                    "conversation messages",
                    []
                );

                return;
            }


            const query = `
                SELECT
                    id,
                    sender_id,
                    receiver_id,
                    username,
                    message,
                    message_type,
                    image_data,
                    created_at,
                    status
                FROM messages
                WHERE
                    (sender_id = ? AND receiver_id = ?)
                    OR
                    (sender_id = ? AND receiver_id = ?)
                ORDER BY id ASC
            `;

            db.query(
                query,
                [
                    me,
                    other,
                    other,
                    me
                ],
                (err, rows) => {

                    if (err) {

                        console.error(
                            "Load conversation error:",
                            err
                        );

                        return;
                    }


                    socket.emit(
                        "conversation messages",
                        rows
                    );
                }
            );
        }
    );


 // ===============================
// SEND PRIVATE MESSAGE
// TEXT + IMAGE
// ===============================

socket.on(
    "chat message",
    (data) => {

        console.log("CHAT DATA RECEIVED:", data);

        const receiverId =
            Number(
                data &&
                data.receiverId
            );

        const messageType =
            data &&
            data.messageType === "image"
                ? "image"
                : "text";


        // ===============================
        // CHECK RECEIVER ID
        // ===============================

        if (
            !Number.isInteger(receiverId) ||
            receiverId <= 0 ||
            receiverId === Number(socket.userId)
        ) {
            console.log("Invalid receiver ID");
            return;
        }


        // ===============================
        // TEXT MESSAGE
        // ===============================

        let message = "";

        if (messageType === "text") {

            message =
                typeof (
                    data &&
                    data.message
                ) === "string"
                    ? data.message.trim()
                    : "";

            if (!message) {
                return;
            }
        }


        // ===============================
        // IMAGE MESSAGE
        // ===============================

        let imageData = null;

        if (messageType === "image") {

            imageData =
                typeof (
                    data &&
                    data.imageData
                ) === "string"
                    ? data.imageData
                    : null;

            if (!imageData) {
                console.log("Image data missing");
                return;
            }


            // Basic image validation

            if (
                !imageData.startsWith(
                    "data:image/"
                )
            ) {

                console.log(
                    "Invalid image data"
                );

                return;
            }


            // Limit image size

            if (
                imageData.length >
                5 * 1024 * 1024
            ) {

                console.log(
                    "Image is too large"
                );

                socket.emit(
                    "image error",
                    "Image is too large. Maximum size is 5 MB."
                );

                return;
            }
        }


        // ===============================
        // CHECK RECEIVER EXISTS
        // ===============================

        db.query(
            "SELECT id, username FROM users WHERE id = ?",
            [receiverId],
            (err, users) => {

                if (
                    err ||
                    users.length === 0
                ) {

                    console.log(
                        "Receiver not found"
                    );

                    return;
                }


                // ===============================
                // SAVE MESSAGE
                // ===============================

                const query = `
                    INSERT INTO messages
                    (
                        sender_id,
                        receiver_id,
                        username,
                        message,
                        message_type,
                        image_data,
                        status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `;


                db.query(
                    query,
                    [
                        socket.userId,
                        receiverId,
                        socket.username,
                        message,
                        messageType,
                        imageData,
                        "sent"
                    ],
                    (err, result) => {

                        if (err) {

                            console.error(
                                "Save message error:",
                                err
                            );

                            return;
                        }


                        // ===============================
                        // MESSAGE DATA
                        // ===============================

                        const messageData = {

                            id:
                                result.insertId,

                            sender_id:
                                socket.userId,

                            receiver_id:
                                receiverId,

                            username:
                                socket.username,

                            message:
                                message,

                            message_type:
                                messageType,

                            image_data:
                                imageData,

                            created_at:
                                new Date(),

                            status:
                                "sent"
                        };


                        // ===============================
                        // SEND TO SENDER
                        // ===============================

                        socket.emit(
                            "chat message",
                            messageData
                        );


                        // ===============================
                        // SEND ONLY TO RECEIVER
                        // ===============================

                        emitToUser(
                            receiverId,
                            "chat message",
                            messageData
                        );


                        // ===============================
                        // UPDATE CHAT LIST
                        // ===============================

                        sendChatList(
                            socket.userId
                        );

                        sendChatList(
                            receiverId
                        );


                        // ===============================
                        // CHECK RECEIVER ONLINE
                        // ===============================

                        const receiverOnline =
                            Object.values(
                                onlineUsers
                            ).some(
                                user =>
                                    Number(
                                        user.userId
                                    ) ===
                                    receiverId
                            );


                        // ===============================
                        // DELIVERED
                        // ===============================

                        if (
                            receiverOnline
                        ) {

                            db.query(
                                `UPDATE messages
                                 SET status = 'delivered'
                                 WHERE id = ?`,
                                [
                                    result.insertId
                                ],
                                (err) => {

                                    if (err) {

                                        console.error(
                                            "Delivery update error:",
                                            err
                                        );

                                        return;
                                    }


                                    // Tell sender

                                    socket.emit(
                                        "message delivered",
                                        result.insertId
                                    );


                                    // Update chat lists

                                    sendChatList(
                                        socket.userId
                                    );

                                    sendChatList(
                                        receiverId
                                    );


                                    // Tell receiver

                                    emitToUser(
                                        receiverId,
                                        "message delivered",
                                        result.insertId
                                    );

                                }
                            );

                        }

                    }
                );

            }
        );

    }
);


    // ===============================
    // READ MESSAGE
    // ===============================

    socket.on(
        "message read",
        (messageId) => {

            const id =
                Number(messageId);


            if (
                !Number.isInteger(id) ||
                id <= 0
            ) {
                return;
            }


            db.query(
                `SELECT
                    sender_id,
                    receiver_id
                 FROM messages
                 WHERE id = ?`,
                [id],
                (err, rows) => {

                    if (
                        err ||
                        rows.length === 0
                    ) {
                        return;
                    }


                    const message =
                        rows[0];


                    // Only receiver can mark it read
                    if (
                        Number(
                            message.receiver_id
                        ) !==
                        Number(
                            socket.userId
                        )
                    ) {
                        return;
                    }


                    db.query(
                        `UPDATE messages
                         SET status = 'read'
                         WHERE id = ?
                         AND receiver_id = ?`,
                        [
                            id,
                            socket.userId
                        ],
                        (err) => {

                            if (err) {

                                console.error(
                                    "Read update error:",
                                    err
                                );

                                return;
                            }


                            // Tell sender
                            emitToUser(
                                message.sender_id,
                                "message read",
                                id
                            );
                        }
                    );
                }
            );
        }
    );


    // ===============================
    // TYPING
    // ===============================

    socket.on(
        "typing",
        (receiverId) => {

            const id =
                Number(receiverId);

            if (
                id > 0 &&
                id !==
                    Number(socket.userId)
            ) {

                emitToUser(
                    id,
                    "user typing",
                    socket.username
                );
            }
        }
    );


    // ===============================
    // STOP TYPING
    // ===============================

    socket.on(
        "stop typing",
        (receiverId) => {

            const id =
                Number(receiverId);

            if (
                id > 0 &&
                id !==
                    Number(socket.userId)
            ) {

                emitToUser(
                    id,
                    "user stopped typing"
                );
            }
        }
    );


    // ===============================
    // DISCONNECT
    // ===============================

    socket.on(
        "disconnect",
        () => {

            delete onlineUsers[
                socket.id
            ];

            sendUserList();

            console.log(
                "DISCONNECTED:",
                socket.username
            );
        }
    );
});


// ===============================
// START SERVER
// ===============================

server.listen(
    PORT,
    "0.0.0.0",
    () => {
        console.log(
            `Server running on port ${PORT}`
        );
    }
);
