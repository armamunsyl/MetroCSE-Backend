const express = require("express");
const { MongoClient, ServerApiVersion } = require('mongodb');
const jwt = require("jsonwebtoken");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
require('dotenv').config();
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3000;

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 2 * 1024 * 1024 }
});

app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.zazcspq.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

const verifyJWT = (req, res, next) => {
    const authorization = req.headers.authorization;
    if (!authorization) {
        return res.status(401).send({ message: "Unauthorized access" });
    }

    const token = authorization.split(" ")[1];
    if (!token) {
        return res.status(401).send({ message: "Unauthorized access" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (error, decoded) => {
        if (error) {
            return res.status(401).send({ message: "Unauthorized access" });
        }
        req.decoded = decoded;
        next();
    });
};

app.get('/', (req, res) => {
    res.send("MetroCSE Hub server is available");
});

app.post("/jwt", (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).send({ message: "Email is required to generate token." });
        }
        const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1d" });
        res.send({ token });
    } catch (error) {
        console.error("Failed to generate token", error);
        res.status(500).send({ message: "Failed to generate token." });
    }
});

async function run() {
    try {
        // await client.connect();
        const db = client.db("MetroCSE");
        const usersCollection = db.collection("users");

        app.get("/users/check", async (req, res) => {
            try {
                const studentId = String(req.query.studentId || "").trim();
                if (!studentId) {
                    return res.status(400).send({ message: "studentId is required." });
                }

                const existingUser = await usersCollection.findOne({ studentId });
                res.send({ exists: Boolean(existingUser) });
            } catch (error) {
                console.error("Failed to check user id", error);
                res.status(500).send({ message: "Failed to check user id." });
            }
        });

        app.get("/users/profile", verifyJWT, async (req, res) => {
            try {
                const email = req.decoded?.email;
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const user = await usersCollection.findOne({ email: email.toLowerCase() });
                if (!user) {
                    return res.status(404).send({ message: "User not found." });
                }

                res.send(user);
            } catch (error) {
                console.error("Failed to fetch user profile", error);
                res.status(500).send({ message: "Failed to fetch user profile." });
            }
        });

        app.patch("/users/profile/image", verifyJWT, async (req, res) => {
            try {
                const email = req.decoded?.email;
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const { imageUrl } = req.body;
                if (!imageUrl) {
                    return res.status(400).send({ message: "imageUrl is required." });
                }

                const result = await usersCollection.updateOne(
                    { email: email.toLowerCase() },
                    { $set: { imageUrl } }
                );

                res.send(result);
            } catch (error) {
                console.error("Failed to update profile image", error);
                res.status(500).send({ message: "Failed to update profile image." });
            }
        });

        app.post("/upload/avatar", verifyJWT, upload.single("image"), async (req, res) => {
            try {
                if (!req.file) {
                    return res.status(400).send({ message: "Image file is required." });
                }

                if (!req.file.mimetype.startsWith("image/")) {
                    return res.status(400).send({ message: "Invalid image format." });
                }

                const uploadResult = await new Promise((resolve, reject) => {
                    const stream = cloudinary.uploader.upload_stream(
                        { folder: "metrocse/avatars", resource_type: "image" },
                        (error, result) => {
                            if (error) {
                                reject(error);
                            } else {
                                resolve(result);
                            }
                        }
                    );
                    stream.end(req.file.buffer);
                });

                res.send({ url: uploadResult.secure_url, publicId: uploadResult.public_id });
            } catch (error) {
                console.error("Failed to upload avatar", error);
                res.status(500).send({ message: "Failed to upload avatar." });
            }
        });

        app.post("/users", verifyJWT, async (req, res) => {
            try {
                const {
                    name,
                    email,
                    imageUrl,
                    gender,
                    studentId,
                    batch,
                    section
                } = req.body;

                if (!name || !email || !studentId || !batch || !section) {
                    return res.status(400).send({ message: "Missing required user fields." });
                }

                const normalizedEmail = email.toLowerCase();
                if (normalizedEmail !== req.decoded?.email) {
                    return res.status(403).send({ message: "Forbidden access" });
                }
                const existingUser = await usersCollection.findOne({
                    $or: [{ email: normalizedEmail }, { studentId: String(studentId) }]
                });
                if (existingUser) {
                    if (existingUser.studentId === String(studentId)) {
                        return res.status(409).send({ message: "User of this ID already exists." });
                    }
                    return res.status(200).send({ acknowledged: true, insertedId: existingUser._id });
                }

                const user = {
                    name,
                    email: normalizedEmail,
                    imageUrl: imageUrl || "",
                    gender: gender || "",
                    studentId: String(studentId),
                    batch,
                    section,
                    role: "Student",
                    status: "Pending",
                    approvedBy: "none",
                    contributionScore: 0,
                    createdAt: new Date()
                };

                const result = await usersCollection.insertOne(user);
                res.send(result);
            } catch (error) {
                console.error("Failed to create user", error);
                res.status(500).send({ message: "Failed to create user." });
            }
        });
    } catch (error) {
        console.error("Failed to initialize database", error);
    }
}
run().catch(console.dir);

// module.exports = app;


app.listen(port, () => {
    console.log(`MetroCSE Hub server is running on port: ${port}`);
});
