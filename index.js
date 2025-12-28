const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
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
        const questionsCollection = db.collection("questions");

        const verifyAdmin = async (req, res, next) => {
            try {
                const email = req.decoded?.email;
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const adminUser = await usersCollection.findOne(
                    { email: email.toLowerCase() },
                    { projection: { role: 1 } }
                );
                if (!adminUser || adminUser.role !== "Admin") {
                    return res.status(403).send({ message: "Forbidden access" });
                }
                next();
            } catch (error) {
                console.error("Failed to verify admin", error);
                res.status(500).send({ message: "Failed to verify admin." });
            }
        };

        const verifyStaff = async (req, res, next) => {
            try {
                const email = req.decoded?.email;
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const staffUser = await usersCollection.findOne(
                    { email: email.toLowerCase() },
                    { projection: { role: 1, batch: 1, section: 1 } }
                );
                const role = String(staffUser?.role || "").toLowerCase();
                const allowedRoles = ["admin", "moderator", "cr"];
                if (!allowedRoles.includes(role)) {
                    return res.status(403).send({ message: "Forbidden access" });
                }
                req.staffUser = staffUser;
                next();
            } catch (error) {
                console.error("Failed to verify staff", error);
                res.status(500).send({ message: "Failed to verify staff." });
            }
        };

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

        app.get("/users/section-cr", verifyJWT, async (req, res) => {
            try {
                const email = req.decoded?.email;
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const user = await usersCollection.findOne(
                    { email: email.toLowerCase() },
                    { projection: { batch: 1, section: 1 } }
                );
                if (!user) {
                    return res.status(404).send({ message: "User not found." });
                }

                if (!user.batch || !user.section) {
                    return res.status(400).send({ message: "Batch and section are required." });
                }

                const cr = await usersCollection.findOne(
                    {
                        batch: user.batch,
                        section: user.section,
                        role: { $regex: /^cr$/i },
                        status: { $regex: /^approved$/i }
                    },
                    { projection: { name: 1, email: 1 } }
                );

                res.send({
                    name: cr?.name || "",
                    email: cr?.email || "",
                    batch: user.batch,
                    section: user.section
                });
            } catch (error) {
                console.error("Failed to fetch section CR", error);
                res.status(500).send({ message: "Failed to fetch section CR." });
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

        app.post("/upload/question-image", verifyJWT, upload.single("image"), async (req, res) => {
            try {
                if (!req.file) {
                    return res.status(400).send({ message: "Image file is required." });
                }

                if (!req.file.mimetype.startsWith("image/")) {
                    return res.status(400).send({ message: "Invalid image format." });
                }

                const uploadResult = await new Promise((resolve, reject) => {
                    const stream = cloudinary.uploader.upload_stream(
                        { folder: "metrocse/questions", resource_type: "image" },
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
                console.error("Failed to upload question image", error);
                res.status(500).send({ message: "Failed to upload question image." });
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

        app.post("/questions", verifyJWT, async (req, res) => {
            try {
                const email = req.decoded?.email;
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const {
                    subjectName,
                    courseCode,
                    batch,
                    semester,
                    type,
                    section,
                    facultyName,
                    questionImageUrl,
                    uploaderComment
                } = req.body;

                if (!subjectName || !courseCode || !batch || !semester || !type) {
                    return res.status(400).send({ message: "Missing required question fields." });
                }

                const normalizedType = String(type).trim();
                const isCt = normalizedType.toLowerCase() === "ct";
                if (isCt && (!section || !facultyName)) {
                    return res.status(400).send({ message: "Section and faculty name are required for CT." });
                }

                const user = await usersCollection.findOne(
                    { email: email.toLowerCase() },
                    { projection: { name: 1, email: 1 } }
                );
                if (!user) {
                    return res.status(404).send({ message: "User not found." });
                }

                const questionDoc = {
                    subjectName,
                    courseCode,
                    batch,
                    semester,
                    type: normalizedType,
                    section: isCt ? section : "",
                    facultyName: isCt ? facultyName : "",
                    questionImageUrl: questionImageUrl || "",
                    uploaderComment: uploaderComment || "",
                    uploaderName: user.name || "",
                    uploaderEmail: user.email,
                    approvedBy: "none",
                    status: "Pending",
                    isReported: false,
                    isEdited: false,
                    createdAt: new Date()
                };

                const result = await questionsCollection.insertOne(questionDoc);
                res.send(result);
            } catch (error) {
                console.error("Failed to create question", error);
                res.status(500).send({ message: "Failed to create question." });
            }
        });

        app.get("/questions", verifyJWT, async (req, res) => {
            try {
                const statusMap = {
                    pending: "Pending",
                    approved: "Approved",
                    rejected: "Rejected"
                };
                const statusQuery = String(req.query.status || "Approved").trim().toLowerCase();
                const status = statusMap[statusQuery] || "Approved";

                const questions = await questionsCollection.aggregate([
                    { $match: { status } },
                    {
                        $lookup: {
                            from: "users",
                            localField: "uploaderEmail",
                            foreignField: "email",
                            as: "uploader"
                        }
                    },
                    { $addFields: { uploader: { $arrayElemAt: ["$uploader", 0] } } },
                    {
                        $project: {
                            _id: 1,
                            subjectName: 1,
                            batch: 1,
                            uploaderName: { $ifNull: ["$uploader.name", "$uploaderName"] },
                            uploaderBatch: "$uploader.batch",
                            uploaderRole: "$uploader.role",
                            uploaderScore: "$uploader.contributionScore",
                            uploaderImage: "$uploader.imageUrl",
                            createdAt: 1
                        }
                    },
                    { $sort: { createdAt: -1 } }
                ]).toArray();

                res.send(questions);
            } catch (error) {
                console.error("Failed to fetch questions", error);
                res.status(500).send({ message: "Failed to fetch questions." });
            }
        });

        app.get("/questions/:id", verifyJWT, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid question id." });
                }

                const question = await questionsCollection.findOne({ _id: new ObjectId(id) });
                if (!question) {
                    return res.status(404).send({ message: "Question not found." });
                }

                if (String(question.status || "").toLowerCase() !== "approved") {
                    return res.status(403).send({ message: "Only approved questions are accessible." });
                }

                const uploader = await usersCollection.findOne(
                    { email: question.uploaderEmail },
                    { projection: { name: 1, batch: 1, section: 1, role: 1, contributionScore: 1, imageUrl: 1 } }
                );

                res.send({
                    _id: question._id,
                    subjectName: question.subjectName || "",
                    courseCode: question.courseCode || "",
                    batch: question.batch || "",
                    semester: question.semester || "",
                    type: question.type || "",
                    section: question.section || "",
                    facultyName: question.facultyName || "",
                    questionImageUrl: question.questionImageUrl || "",
                    uploaderComment: question.uploaderComment || "",
                    uploaderName: uploader?.name || question.uploaderName || "",
                    uploaderBatch: uploader?.batch || "",
                    uploaderSection: uploader?.section || "",
                    uploaderRole: uploader?.role || "Student",
                    uploaderScore: uploader?.contributionScore ?? 0,
                    uploaderImage: uploader?.imageUrl || ""
                });
            } catch (error) {
                console.error("Failed to fetch question details", error);
                res.status(500).send({ message: "Failed to fetch question details." });
            }
        });

        app.get("/contributions", verifyJWT, verifyStaff, async (req, res) => {
            try {
                const status = String(req.query.status || "Pending");
                const role = String(req.staffUser?.role || "").toLowerCase();
                const filters = { status };
                if (role === "cr" || role === "moderator") {
                    filters.batch = req.staffUser?.batch;
                    filters.$or = [
                        { type: { $regex: /^final$/i } },
                        { section: req.staffUser?.section }
                    ];
                }

                const questions = await questionsCollection
                    .find(filters)
                    .project({ subjectName: 1, uploaderName: 1, batch: 1, section: 1, status: 1 })
                    .toArray();

                res.send(questions);
            } catch (error) {
                console.error("Failed to fetch contributions", error);
                res.status(500).send({ message: "Failed to fetch contributions." });
            }
        });

        app.get("/contributions/:id", verifyJWT, verifyStaff, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid question id." });
                }

                const question = await questionsCollection.findOne({ _id: new ObjectId(id) });
                if (!question) {
                    return res.status(404).send({ message: "Question not found." });
                }

                const role = String(req.staffUser?.role || "").toLowerCase();
                const isFinal = String(question.type || "").toLowerCase() === "final";
                if (role === "cr" || role === "moderator") {
                    if (question.batch !== req.staffUser?.batch) {
                        return res.status(403).send({ message: "Forbidden access" });
                    }
                    if (!isFinal && question.section !== req.staffUser?.section) {
                        return res.status(403).send({ message: "Forbidden access" });
                    }
                }

                const uploader = await usersCollection.findOne(
                    { email: question.uploaderEmail },
                    { projection: { batch: 1, section: 1, contributionScore: 1, imageUrl: 1, name: 1 } }
                );

                res.send({
                    ...question,
                    uploaderBatch: uploader?.batch || "",
                    uploaderSection: uploader?.section || "",
                    uploaderContributionScore: uploader?.contributionScore ?? 0,
                    uploaderProfileImage: uploader?.imageUrl || "",
                    uploaderName: uploader?.name || question.uploaderName || ""
                });
            } catch (error) {
                console.error("Failed to fetch contribution details", error);
                res.status(500).send({ message: "Failed to fetch contribution details." });
            }
        });

        app.patch("/contributions/:id", verifyJWT, verifyStaff, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid question id." });
                }

                const { action } = req.body;
                const normalizedAction = String(action || "").toLowerCase();
                if (!["approve", "reject"].includes(normalizedAction)) {
                    return res.status(400).send({ message: "Invalid action." });
                }

                const question = await questionsCollection.findOne({ _id: new ObjectId(id) });
                if (!question) {
                    return res.status(404).send({ message: "Question not found." });
                }
                if (String(question.status || "").toLowerCase() !== "pending") {
                    return res.status(400).send({ message: "Only pending questions can be updated." });
                }

                const role = String(req.staffUser?.role || "").toLowerCase();
                const isFinal = String(question.type || "").toLowerCase() === "final";
                if (role === "cr" || role === "moderator") {
                    if (question.batch !== req.staffUser?.batch) {
                        return res.status(403).send({ message: "Forbidden access" });
                    }
                    if (!isFinal && question.section !== req.staffUser?.section) {
                        return res.status(403).send({ message: "Forbidden access" });
                    }
                }

                const nextStatus = normalizedAction === "approve" ? "Approved" : "Rejected";
                const approvedBy = req.decoded?.email?.toLowerCase() || "system";

                const result = await questionsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { status: nextStatus, approvedBy } }
                );

                if (normalizedAction === "approve" && question.uploaderEmail) {
                    const scoreDelta = isFinal ? 3 : 2;
                    await usersCollection.updateOne(
                        { email: question.uploaderEmail },
                        { $inc: { contributionScore: scoreDelta } }
                    );
                }

                res.send(result);
            } catch (error) {
                console.error("Failed to update contribution", error);
                res.status(500).send({ message: "Failed to update contribution." });
            }
        });

        app.get("/admin/users", verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const users = await usersCollection
                    .find({})
                    .project({ name: 1, email: 1, batch: 1, section: 1, role: 1, studentId: 1 })
                    .toArray();
                res.send(users);
            } catch (error) {
                console.error("Failed to fetch users", error);
                res.status(500).send({ message: "Failed to fetch users." });
            }
        });

        app.get("/admin/users/:id", verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid user id." });
                }

                const user = await usersCollection.findOne({ _id: new ObjectId(id) });
                if (!user) {
                    return res.status(404).send({ message: "User not found." });
                }

                res.send(user);
            } catch (error) {
                console.error("Failed to fetch user details", error);
                res.status(500).send({ message: "Failed to fetch user details." });
            }
        });

        app.patch("/admin/users/:id/role", verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid user id." });
                }

                const roleMap = {
                    student: "Student",
                    cr: "CR",
                    moderator: "Moderator",
                    admin: "Admin"
                };
                const requestedRole = String(req.body?.role || "").trim().toLowerCase();
                const nextRole = roleMap[requestedRole];
                if (!nextRole) {
                    return res.status(400).send({ message: "Invalid role." });
                }

                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { role: nextRole } }
                );

                res.send(result);
            } catch (error) {
                console.error("Failed to update user role", error);
                res.status(500).send({ message: "Failed to update user role." });
            }
        });

        app.get("/admin/approvals", verifyJWT, verifyStaff, async (req, res) => {
            try {
                const status = String(req.query.status || "Pending");
                const role = String(req.staffUser?.role || "").toLowerCase();
                const filters = { status };
                if (role === "cr" || role === "moderator") {
                    filters.batch = req.staffUser?.batch;
                    filters.section = req.staffUser?.section;
                }
                const users = await usersCollection
                    .find(filters)
                    .project({ name: 1, batch: 1, status: 1, studentId: 1 })
                    .toArray();
                res.send(users);
            } catch (error) {
                console.error("Failed to fetch pending approvals", error);
                res.status(500).send({ message: "Failed to fetch pending approvals." });
            }
        });

        app.get("/admin/approvals/:id", verifyJWT, verifyStaff, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid user id." });
                }

                const user = await usersCollection.findOne({ _id: new ObjectId(id) });
                if (!user) {
                    return res.status(404).send({ message: "User not found." });
                }
                const role = String(req.staffUser?.role || "").toLowerCase();
                if ((role === "cr" || role === "moderator") &&
                    (user.batch !== req.staffUser?.batch || user.section !== req.staffUser?.section)) {
                    return res.status(403).send({ message: "Forbidden access" });
                }

                res.send(user);
            } catch (error) {
                console.error("Failed to fetch approval details", error);
                res.status(500).send({ message: "Failed to fetch approval details." });
            }
        });

        app.patch("/admin/approvals/:id", verifyJWT, verifyStaff, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid user id." });
                }

                const { action } = req.body;
                const normalizedAction = String(action || "").toLowerCase();
                if (!["approve", "reject"].includes(normalizedAction)) {
                    return res.status(400).send({ message: "Invalid action." });
                }

                const user = await usersCollection.findOne({ _id: new ObjectId(id) });
                if (!user) {
                    return res.status(404).send({ message: "User not found." });
                }
                if (String(user.status || "").toLowerCase() !== "pending") {
                    return res.status(400).send({ message: "Only pending users can be updated." });
                }
                const role = String(req.staffUser?.role || "").toLowerCase();
                if ((role === "cr" || role === "moderator") &&
                    (user.batch !== req.staffUser?.batch || user.section !== req.staffUser?.section)) {
                    return res.status(403).send({ message: "Forbidden access" });
                }

                const nextStatus = normalizedAction === "approve" ? "Approved" : "Rejected";
                const approvedBy = req.decoded?.email?.toLowerCase() || "system";

                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { status: nextStatus, approvedBy } }
                );

                res.send(result);
            } catch (error) {
                console.error("Failed to update approval status", error);
                res.status(500).send({ message: "Failed to update approval status." });
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
