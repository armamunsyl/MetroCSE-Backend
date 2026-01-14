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
    limits: { fileSize: 5 * 1024 * 1024 }
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
        const bannersCollection = db.collection("banners");
        const commentsCollection = db.collection("comments");
        const noticesCollection = db.collection("notices");
        const noticeCommentsCollection = db.collection("notice_comments");
        const feedbackCollection = db.collection("admin_feedback");
        const reportsCollection = db.collection("reports");
        const notificationsCollection = db.collection("notifications");

        const notificationTypes = [
            "contribution_request",
            "notice_request",
            "notice_published",
            "question_published",
            "report_created",
            "question_comment",
            "member_approval"
        ];

        const buildNotificationMatch = (user) => {
            const email = String(user?.email || "").toLowerCase();
            const role = String(user?.role || "").toLowerCase();
            const batch = String(user?.batch || "").trim();
            const section = String(user?.section || "").trim();
            return {
                $or: [
                    { audienceType: "all" },
                    { audienceType: "role", audienceRoles: { $in: [role] } },
                    { audienceType: "user", audienceEmail: email },
                    { audienceType: "batch", audienceBatch: batch },
                    { audienceType: "batch-section", audienceBatch: batch, audienceSection: section }
                ]
            };
        };

        const createNotification = async ({
            type,
            title,
            message,
            audienceType = "all",
            audienceRoles = [],
            audienceEmail = "",
            audienceBatch = "",
            audienceSection = "",
            metadata = {}
        }) => {
            const doc = {
                type: String(type || "").trim(),
                title: String(title || "").trim(),
                message: String(message || "").trim(),
                audienceType,
                audienceRoles,
                audienceEmail,
                audienceBatch,
                audienceSection,
                metadata,
                createdAt: new Date()
            };
            await notificationsCollection.insertOne(doc);
        };

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
                    { projection: { role: 1, batch: 1, section: 1, name: 1 } }
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


        app.post("/upload/banner-image", verifyJWT, verifyAdmin, upload.single("image"), async (req, res) => {
            try {
                if (!req.file) {
                    return res.status(400).send({ message: "Image file is required." });
                }

                if (!req.file.mimetype.startsWith("image/")) {
                    return res.status(400).send({ message: "Invalid image format." });
                }

                const uploadResult = await new Promise((resolve, reject) => {
                    const stream = cloudinary.uploader.upload_stream(
                        { folder: "metrocse/banners", resource_type: "image" },
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
                console.error("Failed to upload banner image", error);
                res.status(500).send({ message: "Failed to upload banner image." });
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
                await createNotification({
                    type: "member_approval",
                    title: "New member approval",
                    message: `New member request: ${name} (CSE ${batch}${section ? ` Sec ${section}` : ""}).`,
                    audienceType: "role",
                    audienceRoles: ["admin", "moderator", "cr"],
                    metadata: {
                        userEmail: normalizedEmail,
                        batch,
                        section
                    }
                });
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
                    questionImageUrls,
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

                const normalizedImageUrls = Array.isArray(questionImageUrls)
                    ? questionImageUrls.filter(Boolean)
                    : [];
                const primaryImageUrl = questionImageUrl || normalizedImageUrls[0] || "";

                const questionDoc = {
                    subjectName,
                    courseCode,
                    batch,
                    semester,
                    type: normalizedType,
                    section: isCt ? section : "",
                    facultyName: isCt ? facultyName : "",
                    questionImageUrl: primaryImageUrl,
                    questionImageUrls: normalizedImageUrls,
                    uploaderComment: uploaderComment || "",
                    uploaderName: user.name || "",
                    uploaderEmail: user.email,
                    approvedBy: "none",
                    status: "Pending",
                    feedback: [],
                    isReported: false,
                    isEdited: false,
                    createdAt: new Date()
                };

                const result = await questionsCollection.insertOne(questionDoc);
                await createNotification({
                    type: "contribution_request",
                    title: "New contribution request",
                    message: `New contribution submitted: ${subjectName} (${courseCode}).`,
                    audienceType: "role",
                    audienceRoles: ["admin", "moderator", "cr"],
                    metadata: {
                        questionId: result.insertedId,
                        batch,
                        section,
                        type: normalizedType
                    }
                });
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

                const escapeRegex = (value) => String(value || '').replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
                const filters = { status };

                const search = String(req.query.search || '').trim();
                if (search) {
                    const regex = new RegExp(escapeRegex(search), "i");
                    filters.$or = [
                        { subjectName: regex },
                        { courseCode: regex },
                        { batch: regex },
                        { semester: regex },
                        { section: regex },
                        { type: regex },
                        { facultyName: regex },
                        { uploaderName: regex }
                    ];
                }

                const batchParam = String(req.query.batch || '').trim();
                if (batchParam) {
                    const normalizedBatch = batchParam.replace(/^cse\s*/i, '').trim();
                    filters.batch = {
                        $regex: new RegExp(`^(?:cse\\s*)?${escapeRegex(normalizedBatch)}$`, "i")
                    };
                }

                const sectionParam = String(req.query.section || '').trim();
                if (sectionParam) {
                    const normalizedSection = sectionParam.replace(/^sec\s*/i, '').trim();
                    filters.section = new RegExp(`^${escapeRegex(normalizedSection)}$`, "i");
                }

                const semesterParam = String(req.query.semester || '').trim();
                if (semesterParam) {
                    filters.semester = semesterParam;
                }

                const typeParam = String(req.query.type || '').trim();
                if (typeParam) {
                    filters.type = new RegExp(`^${escapeRegex(typeParam)}$`, "i");
                }

                const subjectParam = String(req.query.subject || '').trim();
                if (subjectParam) {
                    filters.subjectName = subjectParam;
                }

                const page = Math.max(1, parseInt(req.query.page || "1", 10));
                const limit = Math.max(1, parseInt(req.query.limit || "10", 10));
                const skip = (page - 1) * limit;

                const shouldPaginate = Boolean(
                    req.query.page ||
                    req.query.limit ||
                    req.query.search ||
                    req.query.batch ||
                    req.query.section ||
                    req.query.semester ||
                    req.query.type ||
                    req.query.subject
                );

                if (!shouldPaginate) {
                    const questions = await questionsCollection.aggregate([
                        { $match: filters },
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
                                courseCode: 1,
                                batch: 1,
                                section: 1,
                                semester: 1,
                                type: 1,
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

                    return res.send(questions);
                }

                const aggregateResult = await questionsCollection.aggregate([
                    { $match: filters },
                    {
                        $facet: {
                            items: [
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
                                        courseCode: 1,
                                        batch: 1,
                                        section: 1,
                                        semester: 1,
                                        type: 1,
                                        uploaderName: { $ifNull: ["$uploader.name", "$uploaderName"] },
                                        uploaderBatch: "$uploader.batch",
                                        uploaderRole: "$uploader.role",
                                        uploaderScore: "$uploader.contributionScore",
                                        uploaderImage: "$uploader.imageUrl",
                                        createdAt: 1
                                    }
                                },
                                { $sort: { createdAt: -1 } },
                                { $skip: skip },
                                { $limit: limit }
                            ],
                            total: [
                                { $count: "count" }
                            ]
                        }
                    }
                ]).toArray();

                const result = aggregateResult[0] || { items: [], total: [] };
                const total = result.total[0]?.count || 0;
                res.send({ items: result.items, total });
            } catch (error) {
                console.error("Failed to fetch questions", error);
                res.status(500).send({ message: "Failed to fetch questions." });
            }
        });

        app.get("/banners", async (req, res) => {
            try {
                const banners = await bannersCollection
                    .find({ isActive: true })
                    .sort({ order: 1, createdAt: -1 })
                    .project({ title: 1, imageUrl: 1, linkUrl: 1, isActive: 1, order: 1 })
                    .toArray();
                res.send(banners);
            } catch (error) {
                console.error("Failed to fetch banners", error);
                res.status(500).send({ message: "Failed to fetch banners." });
            }
        });

        app.get("/notifications/summary", verifyJWT, async (req, res) => {
            try {
                const email = String(req.decoded?.email || "").toLowerCase();
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const user = await usersCollection.findOne({ email });
                if (!user) {
                    return res.status(404).send({ message: "User not found." });
                }

                const readAt = user.notificationsReadAt ? new Date(user.notificationsReadAt) : new Date(0);
                const readAtByType = user.notificationsReadAtByType || {};
                const match = buildNotificationMatch(user);

                const counts = await Promise.all(
                    notificationTypes.map(async (type) => {
                        const typeReadAt = readAtByType[type] ? new Date(readAtByType[type]) : readAt;
                        const count = await notificationsCollection.countDocuments({
                            ...match,
                            type,
                            createdAt: { $gt: typeReadAt }
                        });
                        return { type, count };
                    })
                );

                const typeCounts = counts.reduce((acc, item) => {
                    acc[item.type] = item.count;
                    return acc;
                }, {});

                const unreadCount = counts.reduce((total, item) => total + item.count, 0);

                res.send({ unreadCount, readAt, unreadByType: typeCounts });
            } catch (error) {
                console.error("Failed to fetch notification summary", error);
                res.status(500).send({ message: "Failed to fetch notifications." });
            }
        });

        app.get("/notifications", verifyJWT, async (req, res) => {
            try {
                const email = String(req.decoded?.email || "").toLowerCase();
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const user = await usersCollection.findOne({ email });
                if (!user) {
                    return res.status(404).send({ message: "User not found." });
                }

                const readAt = user.notificationsReadAt ? new Date(user.notificationsReadAt) : new Date(0);
                const readAtByType = user.notificationsReadAtByType || {};
                const typeParam = String(req.query.type || "").trim();
                const unreadOnly = String(req.query.unreadOnly || "").toLowerCase() === "true";
                const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || "5", 10)));
                const page = Math.max(1, parseInt(req.query.page || "1", 10));
                const skip = (page - 1) * limit;

                const match = buildNotificationMatch(user);
                if (typeParam) {
                    match.type = { $in: typeParam.split(",").map((item) => item.trim()).filter(Boolean) };
                }
                if (unreadOnly) {
                    const typesToFilter = match.type?.$in?.length ? match.type.$in : notificationTypes;
                    const minReadAt = typesToFilter.reduce((minValue, type) => {
                        const typeReadAt = readAtByType[type] ? new Date(readAtByType[type]) : readAt;
                        return typeReadAt < minValue ? typeReadAt : minValue;
                    }, readAt);
                    match.createdAt = { $gt: minReadAt };
                }

                const [items, total] = await Promise.all([
                    notificationsCollection
                        .find(match)
                        .sort({ createdAt: -1 })
                        .skip(skip)
                        .limit(limit)
                        .toArray(),
                    notificationsCollection.countDocuments(match)
                ]);

                const counts = await Promise.all(
                    notificationTypes.map(async (type) => {
                        const typeReadAt = readAtByType[type] ? new Date(readAtByType[type]) : readAt;
                        const count = await notificationsCollection.countDocuments({
                            ...buildNotificationMatch(user),
                            type,
                            createdAt: { $gt: typeReadAt }
                        });
                        return count;
                    })
                );
                const unreadCount = counts.reduce((total, count) => total + count, 0);

                const normalizedItems = items.map((item) => ({
                    id: String(item._id),
                    type: item.type || "",
                    title: item.title || "",
                    message: item.message || "",
                    metadata: item.metadata
                        ? {
                            ...item.metadata,
                            questionId: item.metadata.questionId ? String(item.metadata.questionId) : undefined
                        }
                        : {},
                    createdAt: item.createdAt,
                    isRead: item.createdAt <= (readAtByType[item.type] ? new Date(readAtByType[item.type]) : readAt)
                }));

                res.send({
                    items: normalizedItems,
                    unreadCount,
                    readAt,
                    page,
                    total,
                    totalPages: Math.max(1, Math.ceil(total / limit))
                });
            } catch (error) {
                console.error("Failed to fetch notifications", error);
                res.status(500).send({ message: "Failed to fetch notifications." });
            }
        });

        app.patch("/notifications/read", verifyJWT, async (req, res) => {
            try {
                const email = String(req.decoded?.email || "").toLowerCase();
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const readAt = new Date();
                await usersCollection.updateOne(
                    { email },
                    { $set: { notificationsReadAt: readAt } }
                );

                res.send({ readAt });
            } catch (error) {
                console.error("Failed to mark notifications read", error);
                res.status(500).send({ message: "Failed to update notifications." });
            }
        });

        app.patch("/notifications/read-type", verifyJWT, async (req, res) => {
            try {
                const email = String(req.decoded?.email || "").toLowerCase();
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const types = Array.isArray(req.body?.types)
                    ? req.body.types.map((type) => String(type || "").trim()).filter(Boolean)
                    : [];
                if (!types.length) {
                    return res.status(400).send({ message: "Notification types are required." });
                }

                const now = new Date();
                const updateDoc = types.reduce((acc, type) => {
                    acc[`notificationsReadAtByType.${type}`] = now;
                    return acc;
                }, {});

                await usersCollection.updateOne({ email }, { $set: updateDoc });
                res.send({ readAt: now, types });
            } catch (error) {
                console.error("Failed to mark notifications read by type", error);
                res.status(500).send({ message: "Failed to update notifications." });
            }
        });

        app.get("/dashboard/overview", verifyJWT, async (req, res) => {
            try {
                const email = String(req.decoded?.email || "").toLowerCase();
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const user = await usersCollection.findOne(
                    { email },
                    { projection: { role: 1, batch: 1, section: 1 } }
                );

                const role = String(user?.role || "").toLowerCase();
                const pendingStatus = { $regex: /^pending$/i };
                const approvedStatus = { $regex: /^approved$/i };
                const isStaff = ["admin", "moderator", "cr"].includes(role);

                let pendingFilters = { status: pendingStatus };
                if (!isStaff) {
                    pendingFilters = { status: pendingStatus, uploaderEmail: email };
                } else if (role === "cr" || role === "moderator") {
                    pendingFilters.batch = user?.batch || "";
                    pendingFilters.$or = [
                        { type: { $regex: /^final$/i } },
                        { section: user?.section || "" }
                    ];
                }

                const sinceDate = new Date();
                sinceDate.setDate(sinceDate.getDate() - 30);

                const [
                    totalContributions,
                    pendingRequests,
                    newNotices,
                    recentContributions,
                    recentNotices
                ] = await Promise.all([
                    questionsCollection.countDocuments({ uploaderEmail: email }),
                    questionsCollection.countDocuments(pendingFilters),
                    noticesCollection.countDocuments({ status: approvedStatus, createdAt: { $gte: sinceDate } }),
                    questionsCollection
                        .find({ uploaderEmail: email })
                        .project({ subjectName: 1, courseCode: 1, createdAt: 1 })
                        .sort({ createdAt: -1 })
                        .limit(3)
                        .toArray(),
                    noticesCollection
                        .find({ status: approvedStatus })
                        .project({ title: 1, createdAt: 1 })
                        .sort({ createdAt: -1 })
                        .limit(3)
                        .toArray()
                ]);

                const activityItems = []
                recentContributions.forEach((item) => {
                    const label = item.subjectName || item.courseCode || "a course";
                    activityItems.push({
                        createdAt: item.createdAt || new Date(0),
                        message: `Contribution submitted for ${label}.`
                    });
                });
                recentNotices.forEach((item) => {
                    const label = item.title || "new notice";
                    activityItems.push({
                        createdAt: item.createdAt || new Date(0),
                        message: `Notice posted: ${label}.`
                    });
                });

                activityItems.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
                const recentActivity = activityItems.slice(0, 3).map((item) => item.message);

                res.send({
                    stats: {
                        totalContributions,
                        pendingRequests,
                        newNotices
                    },
                    recentActivity
                });
            } catch (error) {
                console.error("Failed to fetch dashboard overview", error);
                res.status(500).send({ message: "Failed to fetch dashboard overview." });
            }
        });

        app.get("/stats", async (req, res) => {
            try {
                const approvedFilter = { status: { $regex: /^approved$/i } };
                const [statsDoc] = await questionsCollection
                    .aggregate([
                        { $match: approvedFilter },
                        {
                            $group: {
                                _id: null,
                                totalQuestions: { $sum: 1 },
                                batches: { $addToSet: "$batch" },
                                contributors: { $addToSet: "$uploaderEmail" }
                            }
                        }
                    ])
                    .toArray();

                const normalizeBatch = (value) =>
                    String(value || "")
                        .trim()
                        .replace(/^cse\s*/i, "")
                        .trim();

                const rawBatches = Array.isArray(statsDoc?.batches) ? statsDoc.batches : [];
                const rawContributors = Array.isArray(statsDoc?.contributors) ? statsDoc.contributors : [];
                const totalQuestions = statsDoc?.totalQuestions || 0;
                const totalBatches = new Set(rawBatches.map(normalizeBatch).filter(Boolean)).size;
                const totalContributors = new Set(
                    rawContributors.map((value) => String(value || "").trim().toLowerCase()).filter(Boolean)
                ).size;

                res.send({ totalQuestions, totalBatches, totalContributors });
            } catch (error) {
                console.error("Failed to fetch stats", error);
                res.status(500).send({ message: "Failed to fetch stats." });
            }
        });

        app.get("/admin/banners", verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const banners = await bannersCollection
                    .find({})
                    .sort({ order: 1, createdAt: -1 })
                    .toArray();
                res.send(banners);
            } catch (error) {
                console.error("Failed to fetch banners", error);
                res.status(500).send({ message: "Failed to fetch banners." });
            }
        });

        app.post("/admin/banners", verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const { title, imageUrl, linkUrl, isActive, order } = req.body || {};
                if (!imageUrl) {
                    return res.status(400).send({ message: "Banner image is required." });
                }

                const bannerDoc = {
                    title: String(title || "").trim(),
                    imageUrl: String(imageUrl || "").trim(),
                    linkUrl: String(linkUrl || "").trim(),
                    isActive: Boolean(isActive),
                    order: Number.isFinite(Number(order)) ? Number(order) : 0,
                    createdAt: new Date(),
                    updatedAt: new Date()
                };

                const result = await bannersCollection.insertOne(bannerDoc);
                res.send(result);
            } catch (error) {
                console.error("Failed to create banner", error);
                res.status(500).send({ message: "Failed to create banner." });
            }
        });

        app.patch("/admin/banners/:id", verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid banner id." });
                }

                const { title, imageUrl, linkUrl, isActive, order } = req.body || {};
                const updateDoc = { updatedAt: new Date() };

                if (title !== undefined) updateDoc.title = String(title || "").trim();
                if (imageUrl !== undefined) updateDoc.imageUrl = String(imageUrl || "").trim();
                if (linkUrl !== undefined) updateDoc.linkUrl = String(linkUrl || "").trim();
                if (isActive !== undefined) updateDoc.isActive = Boolean(isActive);
                if (order !== undefined && Number.isFinite(Number(order))) {
                    updateDoc.order = Number(order);
                }

                const result = await bannersCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: updateDoc }
                );
                res.send(result);
            } catch (error) {
                console.error("Failed to update banner", error);
                res.status(500).send({ message: "Failed to update banner." });
            }
        });

        app.delete("/admin/banners/:id", verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid banner id." });
                }

                const result = await bannersCollection.deleteOne({ _id: new ObjectId(id) });
                res.send(result);
            } catch (error) {
                console.error("Failed to delete banner", error);
                res.status(500).send({ message: "Failed to delete banner." });
            }
        });

        app.get("/notices", verifyJWT, async (req, res) => {
            try {
                const statusMap = {
                    pending: "Pending",
                    approved: "Approved",
                    rejected: "Rejected"
                };
                const statusQuery = String(req.query.status || "Approved").trim().toLowerCase();
                const status = statusMap[statusQuery] || "Approved";

                const notices = await noticesCollection
                    .find({ status })
                    .sort({ createdAt: -1 })
                    .toArray();

                res.send(notices);
            } catch (error) {
                console.error("Failed to fetch notices", error);
                res.status(500).send({ message: "Failed to fetch notices." });
            }
        });

        app.get("/notices/user", verifyJWT, async (req, res) => {
            try {
                const email = req.decoded?.email?.toLowerCase();
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const notices = await noticesCollection
                    .find({ authorEmail: email })
                    .sort({ createdAt: -1 })
                    .toArray();

                res.send(notices);
            } catch (error) {
                console.error("Failed to fetch user notices", error);
                res.status(500).send({ message: "Failed to fetch notices." });
            }
        });

        app.get("/notices/:id", verifyJWT, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid notice id." });
                }

                const notice = await noticesCollection.findOne({ _id: new ObjectId(id) });
                if (!notice) {
                    return res.status(404).send({ message: "Notice not found." });
                }
                if (String(notice.status || "").toLowerCase() !== "approved") {
                    return res.status(403).send({ message: "Only approved notices are accessible." });
                }

                res.send(notice);
            } catch (error) {
                console.error("Failed to fetch notice details", error);
                res.status(500).send({ message: "Failed to fetch notice details." });
            }
        });

        app.post("/notices", verifyJWT, async (req, res) => {
            try {
                const email = req.decoded?.email;
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const { title, description } = req.body || {};
                const normalizedTitle = String(title || "").trim();
                const normalizedDescription = String(description || "").trim();
                if (!normalizedTitle || !normalizedDescription) {
                    return res.status(400).send({ message: "Title and description are required." });
                }

                const user = await usersCollection.findOne(
                    { email: email.toLowerCase() },
                    { projection: { name: 1, batch: 1, section: 1, role: 1, imageUrl: 1 } }
                );

                const noticeDoc = {
                    title: normalizedTitle,
                    description: normalizedDescription,
                    status: "Pending",
                    authorEmail: email.toLowerCase(),
                    authorName: user?.name || "",
                    authorBatch: user?.batch || "",
                    authorSection: user?.section || "",
                    authorRole: user?.role || "Student",
                    authorImage: user?.imageUrl || "",
                    createdAt: new Date(),
                    updatedAt: new Date()
                };

                const result = await noticesCollection.insertOne(noticeDoc);
                await createNotification({
                    type: "notice_request",
                    title: "Notice approval request",
                    message: `New notice submitted: ${normalizedTitle}.`,
                    audienceType: "role",
                    audienceRoles: ["admin"],
                    metadata: { noticeId: result.insertedId }
                });
                res.send({ ...noticeDoc, _id: result.insertedId });
            } catch (error) {
                console.error("Failed to create notice", error);
                res.status(500).send({ message: "Failed to create notice." });
            }
        });

        app.delete("/notices/:id", verifyJWT, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid notice id." });
                }

                const email = req.decoded?.email?.toLowerCase();
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const notice = await noticesCollection.findOne({ _id: new ObjectId(id) });
                if (!notice) {
                    return res.status(404).send({ message: "Notice not found." });
                }
                if (notice.authorEmail !== email) {
                    return res.status(403).send({ message: "Forbidden access" });
                }

                const result = await noticesCollection.deleteOne({ _id: new ObjectId(id) });
                res.send(result);
            } catch (error) {
                console.error("Failed to delete notice", error);
                res.status(500).send({ message: "Failed to delete notice." });
            }
        });

        app.get("/notice-comments", verifyJWT, async (req, res) => {
            try {
                const noticeId = String(req.query.noticeId || "").trim();
                if (!ObjectId.isValid(noticeId)) {
                    return res.status(400).send({ message: "Invalid notice id." });
                }

                const notice = await noticesCollection.findOne({ _id: new ObjectId(noticeId) });
                if (!notice) {
                    return res.status(404).send({ message: "Notice not found." });
                }
                if (String(notice.status || "").toLowerCase() !== "approved") {
                    return res.status(403).send({ message: "Only approved notices are accessible." });
                }

                const comments = await noticeCommentsCollection
                    .find({ noticeId: new ObjectId(noticeId) })
                    .sort({ createdAt: -1 })
                    .toArray();
                res.send(comments);
            } catch (error) {
                console.error("Failed to fetch notice comments", error);
                res.status(500).send({ message: "Failed to fetch notice comments." });
            }
        });

        app.post("/notice-comments", verifyJWT, async (req, res) => {
            try {
                const email = req.decoded?.email;
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const { noticeId, message } = req.body || {};
                if (!ObjectId.isValid(noticeId)) {
                    return res.status(400).send({ message: "Invalid notice id." });
                }
                const text = String(message || "").trim();
                if (!text) {
                    return res.status(400).send({ message: "Comment message is required." });
                }

                const notice = await noticesCollection.findOne({ _id: new ObjectId(noticeId) });
                if (!notice) {
                    return res.status(404).send({ message: "Notice not found." });
                }
                if (String(notice.status || "").toLowerCase() !== "approved") {
                    return res.status(403).send({ message: "Only approved notices are accessible." });
                }

                const user = await usersCollection.findOne(
                    { email: email.toLowerCase() },
                    { projection: { name: 1, imageUrl: 1, batch: 1, section: 1, contributionScore: 1, role: 1 } }
                );

                const commentDoc = {
                    noticeId: new ObjectId(noticeId),
                    message: text,
                    authorEmail: email.toLowerCase(),
                    authorName: user?.name || "",
                    authorImage: user?.imageUrl || "",
                    authorBatch: user?.batch || "",
                    authorSection: user?.section || "",
                    authorScore: user?.contributionScore ?? 0,
                    authorRole: user?.role || "Student",
                    createdAt: new Date(),
                    updatedAt: new Date()
                };

                const result = await noticeCommentsCollection.insertOne(commentDoc);
                res.send({ ...commentDoc, _id: result.insertedId });
            } catch (error) {
                console.error("Failed to create notice comment", error);
                res.status(500).send({ message: "Failed to create comment." });
            }
        });

        app.patch("/notice-comments/:id", verifyJWT, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid comment id." });
                }

                const email = req.decoded?.email?.toLowerCase();
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const comment = await noticeCommentsCollection.findOne({ _id: new ObjectId(id) });
                if (!comment) {
                    return res.status(404).send({ message: "Comment not found." });
                }
                if (comment.authorEmail !== email) {
                    return res.status(403).send({ message: "Forbidden access" });
                }

                const message = String(req.body?.message || "").trim();
                if (!message) {
                    return res.status(400).send({ message: "Comment message is required." });
                }

                const result = await noticeCommentsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { message, updatedAt: new Date() } }
                );
                res.send(result);
            } catch (error) {
                console.error("Failed to update notice comment", error);
                res.status(500).send({ message: "Failed to update comment." });
            }
        });

        app.delete("/notice-comments/:id", verifyJWT, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid comment id." });
                }

                const email = req.decoded?.email?.toLowerCase();
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const comment = await noticeCommentsCollection.findOne({ _id: new ObjectId(id) });
                if (!comment) {
                    return res.status(404).send({ message: "Comment not found." });
                }
                if (comment.authorEmail !== email) {
                    return res.status(403).send({ message: "Forbidden access" });
                }

                const result = await noticeCommentsCollection.deleteOne({ _id: new ObjectId(id) });
                res.send(result);
            } catch (error) {
                console.error("Failed to delete notice comment", error);
                res.status(500).send({ message: "Failed to delete comment." });
            }
        });

        app.get("/admin/notices", verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const statusMap = {
                    pending: "Pending",
                    approved: "Approved",
                    rejected: "Rejected"
                };
                const statusQuery = String(req.query.status || "Pending").trim().toLowerCase();
                const status = statusMap[statusQuery] || "Pending";

                const notices = await noticesCollection
                    .find({ status })
                    .sort({ createdAt: -1 })
                    .toArray();

                res.send(notices);
            } catch (error) {
                console.error("Failed to fetch admin notices", error);
                res.status(500).send({ message: "Failed to fetch notices." });
            }
        });

        app.get("/admin/analytics", verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const approvedStatus = { $regex: /^approved$/i };
                const normalizeBatch = (value) =>
                    String(value || "")
                        .trim()
                        .replace(/^cse\s*/i, "")
                        .trim();
                const normalizeSection = (value) =>
                    String(value || "")
                        .trim()
                        .replace(/^sec\s*/i, "")
                        .trim()
                        .toUpperCase();

                const [
                    rawUsersByBatch,
                    rawUsersBySection,
                    rawUsersByBatchSection,
                    rawQuestionsByBatch,
                    rawQuestionsBySection,
                    rawQuestionsByBatchSection,
                    rawUserGraph
                ] = await Promise.all([
                    usersCollection.aggregate([
                        { $group: { _id: "$batch", count: { $sum: 1 } } }
                    ]).toArray(),
                    usersCollection.aggregate([
                        { $group: { _id: "$section", count: { $sum: 1 } } }
                    ]).toArray(),
                    usersCollection.aggregate([
                        { $group: { _id: { batch: "$batch", section: "$section" }, count: { $sum: 1 } } }
                    ]).toArray(),
                    questionsCollection.aggregate([
                        { $match: { status: approvedStatus } },
                        { $group: { _id: "$batch", count: { $sum: 1 } } }
                    ]).toArray(),
                    questionsCollection.aggregate([
                        { $match: { status: approvedStatus } },
                        { $group: { _id: "$section", count: { $sum: 1 } } }
                    ]).toArray(),
                    questionsCollection.aggregate([
                        { $match: { status: approvedStatus } },
                        { $group: { _id: { batch: "$batch", section: "$section" }, count: { $sum: 1 } } }
                    ]).toArray(),
                    usersCollection.aggregate([
                        {
                            $group: {
                                _id: {
                                    $dateToString: { format: "%Y-%m", date: "$createdAt" }
                                },
                                count: { $sum: 1 }
                            }
                        },
                        { $sort: { _id: 1 } },
                        { $limit: 12 }
                    ]).toArray()
                ]);

                const mergeCounts = (items, keyBuilder) => {
                    const map = new Map();
                    items.forEach((item) => {
                        const key = keyBuilder(item);
                        if (!key) return;
                        map.set(key, (map.get(key) || 0) + (item.count || 0));
                    });
                    return Array.from(map.entries())
                        .map(([key, count]) => ({ key, count }))
                        .sort((a, b) => b.count - a.count);
                };

                const usersByBatch = mergeCounts(rawUsersByBatch, (item) => normalizeBatch(item._id));
                const usersBySection = mergeCounts(rawUsersBySection, (item) => normalizeSection(item._id));
                const usersByBatchSection = mergeCounts(rawUsersByBatchSection, (item) => {
                    const batch = normalizeBatch(item?._id?.batch);
                    const section = normalizeSection(item?._id?.section);
                    if (!batch || !section) return "";
                    return `${batch}-${section}`;
                });

                const questionsByBatch = mergeCounts(rawQuestionsByBatch, (item) => normalizeBatch(item._id));
                const questionsBySection = mergeCounts(rawQuestionsBySection, (item) => normalizeSection(item._id));
                const questionsByBatchSection = mergeCounts(rawQuestionsByBatchSection, (item) => {
                    const batch = normalizeBatch(item?._id?.batch);
                    const section = normalizeSection(item?._id?.section);
                    if (!batch || !section) return "";
                    return `${batch}-${section}`;
                });

                const userGraph = rawUserGraph.map((item) => ({
                    label: item._id,
                    count: item.count || 0
                }));

                res.send({
                    usersByBatch,
                    usersBySection,
                    usersByBatchSection,
                    questionsByBatch,
                    questionsBySection,
                    questionsByBatchSection,
                    userGraph
                });
            } catch (error) {
                console.error("Failed to fetch analytics", error);
                res.status(500).send({ message: "Failed to fetch analytics." });
            }
        });

        app.patch("/admin/notices/:id", verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid notice id." });
                }

                const { action } = req.body || {};
                const normalizedAction = String(action || "").toLowerCase();
                if (!["approve", "reject"].includes(normalizedAction)) {
                    return res.status(400).send({ message: "Invalid action." });
                }

                const notice = await noticesCollection.findOne({ _id: new ObjectId(id) });
                if (!notice) {
                    return res.status(404).send({ message: "Notice not found." });
                }
                if (String(notice.status || "").toLowerCase() !== "pending") {
                    return res.status(400).send({ message: "Only pending notices can be updated." });
                }

                const nextStatus = normalizedAction === "approve" ? "Approved" : "Rejected";
                const approvedBy = req.decoded?.email?.toLowerCase() || "system";

                const result = await noticesCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { status: nextStatus, approvedBy, updatedAt: new Date() } }
                );

                if (nextStatus === "Approved") {
                    await createNotification({
                        type: "notice_published",
                        title: "New notice published",
                        message: `Notice published: ${notice.title || "New notice"}.`,
                        audienceType: "all",
                        metadata: { noticeId: notice._id }
                    });
                }

                res.send(result);
            } catch (error) {
                console.error("Failed to update notice", error);
                res.status(500).send({ message: "Failed to update notice." });
            }
        });

        app.get("/feedback", verifyJWT, async (req, res) => {
            try {
                const email = req.decoded?.email?.toLowerCase();
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const feedbacks = await feedbackCollection
                    .find({ toEmail: email })
                    .sort({ createdAt: -1 })
                    .toArray();

                res.send(feedbacks);
            } catch (error) {
                console.error("Failed to fetch admin feedback", error);
                res.status(500).send({ message: "Failed to fetch admin feedback." });
            }
        });

        app.post("/admin/feedback", verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const { title, message, targetEmail, batch, section } = req.body || {};
                const normalizedTitle = String(title || "").trim();
                const normalizedMessage = String(message || "").trim();
                if (!normalizedTitle || !normalizedMessage) {
                    return res.status(400).send({ message: "Title and message are required." });
                }

                const adminEmail = req.decoded?.email?.toLowerCase() || "admin";
                const adminUser = await usersCollection.findOne(
                    { email: adminEmail },
                    { projection: { name: 1 } }
                );

                const normalizedTargetEmail = String(targetEmail || "").trim().toLowerCase();
                const normalizedBatch = String(batch || "").trim().replace(/^cse\s*/i, "");
                const normalizedSection = String(section || "").trim().replace(/^sec\s*/i, "");

                let userQuery = null;
                let targetType = "";
                if (normalizedTargetEmail) {
                    userQuery = { email: normalizedTargetEmail };
                    targetType = "email";
                } else if (normalizedBatch) {
                    userQuery = {
                        batch: {
                            $regex: new RegExp(`^(?:cse\\s*)?${normalizedBatch}$`, "i")
                        }
                    };
                    targetType = normalizedSection ? "batch-section" : "batch";
                    if (normalizedSection) {
                        userQuery.section = new RegExp(`^${normalizedSection}$`, "i");
                    }
                } else {
                    return res.status(400).send({ message: "Target email or batch is required." });
                }

                const users = await usersCollection
                    .find(userQuery)
                    .project({ email: 1, name: 1, batch: 1, section: 1 })
                    .toArray();

                if (!users.length) {
                    return res.status(404).send({ message: "No users found for the selected target." });
                }

                const now = new Date();
                const feedbackDocs = users.map((user) => ({
                    title: normalizedTitle,
                    message: normalizedMessage,
                    toEmail: user.email,
                    toName: user.name || "",
                    toBatch: user.batch || "",
                    toSection: user.section || "",
                    targetType,
                    createdByEmail: adminEmail,
                    createdByName: adminUser?.name || "Admin",
                    createdAt: now
                }));

                const result = await feedbackCollection.insertMany(feedbackDocs);
                res.send({ insertedCount: result.insertedCount });
            } catch (error) {
                console.error("Failed to send admin feedback", error);
                res.status(500).send({ message: "Failed to send admin feedback." });
            }
        });

        app.post("/reports", verifyJWT, async (req, res) => {
            try {
                const email = req.decoded?.email?.toLowerCase();
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const { targetType, targetId } = req.body || {};
                const normalizedType = String(targetType || "").trim().toLowerCase();
                if (!["question", "comment"].includes(normalizedType)) {
                    return res.status(400).send({ message: "Invalid target type." });
                }
                if (!ObjectId.isValid(targetId)) {
                    return res.status(400).send({ message: "Invalid target id." });
                }

                let targetQuestionId = null;
                if (normalizedType === "question") {
                    const question = await questionsCollection.findOne({ _id: new ObjectId(targetId) });
                    if (!question) {
                        return res.status(404).send({ message: "Question not found." });
                    }
                    targetQuestionId = question._id;
                }

                if (normalizedType === "comment") {
                    const comment = await commentsCollection.findOne({ _id: new ObjectId(targetId) });
                    if (!comment) {
                        return res.status(404).send({ message: "Comment not found." });
                    }
                    targetQuestionId = comment.questionId || null;
                }

                const reporter = await usersCollection.findOne(
                    { email },
                    { projection: { name: 1, role: 1, batch: 1, section: 1, imageUrl: 1 } }
                );

                const reportDoc = {
                    targetType: normalizedType,
                    targetId: new ObjectId(targetId),
                    questionId: targetQuestionId,
                    status: "Pending",
                    reporterEmail: email,
                    reporterName: reporter?.name || "",
                    reporterRole: reporter?.role || "Student",
                    reporterBatch: reporter?.batch || "",
                    reporterSection: reporter?.section || "",
                    reporterImage: reporter?.imageUrl || "",
                    createdAt: new Date(),
                    updatedAt: new Date()
                };

                const result = await reportsCollection.insertOne(reportDoc);
                await createNotification({
                    type: "report_created",
                    title: "New report submitted",
                    message: `A new ${normalizedType} report was submitted.`,
                    audienceType: "role",
                    audienceRoles: ["admin"],
                    metadata: {
                        reportId: result.insertedId,
                        targetType: normalizedType
                    }
                });
                res.send({ ...reportDoc, _id: result.insertedId });
            } catch (error) {
                console.error("Failed to create report", error);
                res.status(500).send({ message: "Failed to create report." });
            }
        });

        app.get("/admin/reports", verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const statusMap = {
                    pending: "Pending",
                    ignored: "Ignored",
                    resolved: "Resolved"
                };
                const statusQuery = String(req.query.status || "Pending").trim().toLowerCase();
                const status = statusMap[statusQuery] || "Pending";

                const reports = await reportsCollection
                    .find({ status })
                    .sort({ createdAt: -1 })
                    .toArray();

                res.send(reports);
            } catch (error) {
                console.error("Failed to fetch reports", error);
                res.status(500).send({ message: "Failed to fetch reports." });
            }
        });

        app.get("/admin/reports/:id", verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid report id." });
                }

                const report = await reportsCollection.findOne({ _id: new ObjectId(id) });
                if (!report) {
                    return res.status(404).send({ message: "Report not found." });
                }

                let target = null;
                if (report.targetType === "question") {
                    target = await questionsCollection.findOne({ _id: new ObjectId(report.targetId) });
                } else if (report.targetType === "comment") {
                    target = await commentsCollection.findOne({ _id: new ObjectId(report.targetId) });
                }

                res.send({ report, target });
            } catch (error) {
                console.error("Failed to fetch report details", error);
                res.status(500).send({ message: "Failed to fetch report details." });
            }
        });

        app.patch("/admin/reports/:id", verifyJWT, verifyAdmin, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid report id." });
                }

                const { action } = req.body || {};
                const normalizedAction = String(action || "").trim().toLowerCase();
                if (!["ignore", "delete"].includes(normalizedAction)) {
                    return res.status(400).send({ message: "Invalid action." });
                }

                const report = await reportsCollection.findOne({ _id: new ObjectId(id) });
                if (!report) {
                    return res.status(404).send({ message: "Report not found." });
                }

                if (normalizedAction === "delete") {
                    if (report.targetType === "question") {
                        await questionsCollection.deleteOne({ _id: new ObjectId(report.targetId) });
                        await commentsCollection.deleteMany({ questionId: new ObjectId(report.targetId) });
                    } else if (report.targetType === "comment") {
                        await commentsCollection.deleteOne({ _id: new ObjectId(report.targetId) });
                    }
                }

                const nextStatus = normalizedAction === "ignore" ? "Ignored" : "Resolved";
                const result = await reportsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { status: nextStatus, updatedAt: new Date() } }
                );

                res.send(result);
            } catch (error) {
                console.error("Failed to update report", error);
                res.status(500).send({ message: "Failed to update report." });
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
                    questionImageUrls: Array.isArray(question.questionImageUrls) ? question.questionImageUrls : [],
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

        app.get("/comment", verifyJWT, async (req, res) => {
            try {
                const questionId = String(req.query.questionId || "").trim();
                if (!ObjectId.isValid(questionId)) {
                    return res.status(400).send({ message: "Invalid question id." });
                }

                const comments = await commentsCollection
                    .find({ questionId: new ObjectId(questionId) })
                    .sort({ createdAt: -1 })
                    .toArray();
                res.send(comments);
            } catch (error) {
                console.error("Failed to fetch comments", error);
                res.status(500).send({ message: "Failed to fetch comments." });
            }
        });

        app.get("/comment/user", verifyJWT, async (req, res) => {
            try {
                const email = req.decoded?.email?.toLowerCase();
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const comments = await commentsCollection.aggregate([
                    { $match: { authorEmail: email } },
                    {
                        $lookup: {
                            from: "questions",
                            localField: "questionId",
                            foreignField: "_id",
                            as: "question"
                        }
                    },
                    { $addFields: { question: { $arrayElemAt: ["$question", 0] } } },
                    {
                        $project: {
                            message: 1,
                            authorEmail: 1,
                            authorName: 1,
                            authorImage: 1,
                            authorBatch: 1,
                            authorSection: 1,
                            createdAt: 1,
                            updatedAt: 1,
                            questionId: 1,
                            questionSubject: "$question.subjectName",
                            questionBatch: "$question.batch",
                            questionType: "$question.type"
                        }
                    },
                    { $sort: { createdAt: -1 } }
                ]).toArray();

                res.send(comments);
            } catch (error) {
                console.error("Failed to fetch user comments", error);
                res.status(500).send({ message: "Failed to fetch comments." });
            }
        });

        app.post("/comment", verifyJWT, async (req, res) => {
            try {
                const email = req.decoded?.email;
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const { questionId, message } = req.body || {};
                if (!ObjectId.isValid(questionId)) {
                    return res.status(400).send({ message: "Invalid question id." });
                }
                const text = String(message || "").trim();
                if (!text) {
                    return res.status(400).send({ message: "Comment message is required." });
                }

                const user = await usersCollection.findOne(
                    { email: email.toLowerCase() },
                    { projection: { name: 1, imageUrl: 1, batch: 1, section: 1, contributionScore: 1, role: 1 } }
                );

                const question = await questionsCollection.findOne(
                    { _id: new ObjectId(questionId) },
                    { projection: { uploaderEmail: 1, subjectName: 1, courseCode: 1 } }
                );

                const commentDoc = {
                    questionId: new ObjectId(questionId),
                    message: text,
                    authorEmail: email.toLowerCase(),
                    authorName: user?.name || "",
                    authorImage: user?.imageUrl || "",
                    authorBatch: user?.batch || "",
                    authorSection: user?.section || "",
                    authorScore: user?.contributionScore ?? 0,
                    authorRole: user?.role || "Student",
                    createdAt: new Date(),
                    updatedAt: new Date()
                };

                const result = await commentsCollection.insertOne(commentDoc);
                if (question?.uploaderEmail && question.uploaderEmail !== email.toLowerCase()) {
                    await createNotification({
                        type: "question_comment",
                        title: "New comment on your question",
                        message: `New comment on ${question.subjectName || question.courseCode || "your question"}.`,
                        audienceType: "user",
                        audienceEmail: question.uploaderEmail,
                        metadata: { questionId: question._id }
                    });
                }
                res.send({ ...commentDoc, _id: result.insertedId });
            } catch (error) {
                console.error("Failed to create comment", error);
                res.status(500).send({ message: "Failed to create comment." });
            }
        });

        app.patch("/comment/:id", verifyJWT, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid comment id." });
                }

                const email = req.decoded?.email?.toLowerCase();
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const comment = await commentsCollection.findOne({ _id: new ObjectId(id) });
                if (!comment) {
                    return res.status(404).send({ message: "Comment not found." });
                }
                if (comment.authorEmail !== email) {
                    return res.status(403).send({ message: "Forbidden access" });
                }

                const message = String(req.body?.message || "").trim();
                if (!message) {
                    return res.status(400).send({ message: "Comment message is required." });
                }

                const result = await commentsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { message, updatedAt: new Date() } }
                );
                res.send(result);
            } catch (error) {
                console.error("Failed to update comment", error);
                res.status(500).send({ message: "Failed to update comment." });
            }
        });

        app.delete("/comment/:id", verifyJWT, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid comment id." });
                }

                const email = req.decoded?.email?.toLowerCase();
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const comment = await commentsCollection.findOne({ _id: new ObjectId(id) });
                if (!comment) {
                    return res.status(404).send({ message: "Comment not found." });
                }
                if (comment.authorEmail !== email) {
                    return res.status(403).send({ message: "Forbidden access" });
                }

                const result = await commentsCollection.deleteOne({ _id: new ObjectId(id) });
                res.send(result);
            } catch (error) {
                console.error("Failed to delete comment", error);
                res.status(500).send({ message: "Failed to delete comment." });
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

                const { action, feedback } = req.body;
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

                const updateDoc = { $set: { status: nextStatus, approvedBy } };
                const feedbackText = String(feedback || "").trim();
                if (feedbackText) {
                    updateDoc.$push = {
                        feedback: {
                            message: feedbackText,
                            byEmail: req.decoded?.email?.toLowerCase() || "system",
                            byName: req.staffUser?.name || "",
                            role: req.staffUser?.role || "",
                            createdAt: new Date()
                        }
                    };
                }

                const result = await questionsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    updateDoc
                );

                if (normalizedAction === "approve" && question.uploaderEmail) {
                    const scoreDelta = isFinal ? 3 : 2;
                    await usersCollection.updateOne(
                        { email: question.uploaderEmail },
                        { $inc: { contributionScore: scoreDelta } }
                    );
                    await createNotification({
                        type: "question_published",
                        title: "New question added",
                        message: `New question added: ${question.subjectName || question.courseCode || "New question"}.`,
                        audienceType: "all",
                        metadata: { questionId: question._id }
                    });
                }

                res.send(result);
            } catch (error) {
                console.error("Failed to update contribution", error);
                res.status(500).send({ message: "Failed to update contribution." });
            }
        });

        app.get("/users/contributions", verifyJWT, async (req, res) => {
            try {
                const email = req.decoded?.email;
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const status = String(req.query.status || "").trim();
                const filters = { uploaderEmail: email.toLowerCase() };
                if (status) {
                    filters.status = status;
                }

                const contributions = await questionsCollection
                    .find(filters)
                    .project({
                        subjectName: 1,
                        courseCode: 1,
                        batch: 1,
                        semester: 1,
                        type: 1,
                        section: 1,
                        facultyName: 1,
                        status: 1,
                        uploaderComment: 1,
                        questionImageUrl: 1,
                        createdAt: 1
                    })
                    .sort({ createdAt: -1 })
                    .toArray();

                res.send(contributions);
            } catch (error) {
                console.error("Failed to fetch user contributions", error);
                res.status(500).send({ message: "Failed to fetch user contributions." });
            }
        });

        app.get("/users/contributions/:id", verifyJWT, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid question id." });
                }

                const email = req.decoded?.email;
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const question = await questionsCollection.findOne({ _id: new ObjectId(id) });
                if (!question) {
                    return res.status(404).send({ message: "Question not found." });
                }

                if (String(question.uploaderEmail || "").toLowerCase() !== email.toLowerCase()) {
                    return res.status(403).send({ message: "Forbidden access" });
                }

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
                    status: question.status || "",
                    feedback: question.feedback || []
                });
            } catch (error) {
                console.error("Failed to fetch contribution details", error);
                res.status(500).send({ message: "Failed to fetch contribution details." });
            }
        });

        app.patch("/users/contributions/:id", verifyJWT, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) {
                    return res.status(400).send({ message: "Invalid question id." });
                }

                const email = req.decoded?.email;
                if (!email) {
                    return res.status(401).send({ message: "Unauthorized access" });
                }

                const question = await questionsCollection.findOne({ _id: new ObjectId(id) });
                if (!question) {
                    return res.status(404).send({ message: "Question not found." });
                }

                if (String(question.uploaderEmail || "").toLowerCase() !== email.toLowerCase()) {
                    return res.status(403).send({ message: "Forbidden access" });
                }

                const currentStatus = String(question.status || "").toLowerCase();
                if (!["pending", "rejected"].includes(currentStatus)) {
                    return res.status(400).send({ message: "Only pending or rejected questions can be edited." });
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
                    uploaderComment,
                    status
                } = req.body;

                const updateFields = {
                    subjectName: subjectName ?? question.subjectName,
                    courseCode: courseCode ?? question.courseCode,
                    batch: batch ?? question.batch,
                    semester: semester ?? question.semester,
                    type: type ?? question.type,
                    section: section ?? question.section,
                    facultyName: facultyName ?? question.facultyName,
                    questionImageUrl: questionImageUrl ?? question.questionImageUrl,
                    uploaderComment: uploaderComment ?? question.uploaderComment,
                    isEdited: true
                };

                if (String(question.status || "").toLowerCase() === "rejected" &&
                    String(status || "").toLowerCase() === "pending") {
                    updateFields.status = "Pending";
                }

                const result = await questionsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: updateFields }
                );

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

        app.use((err, req, res, next) => {
            if (err instanceof multer.MulterError) {
                if (err.code === "LIMIT_FILE_SIZE") {
                    return res.status(413).send({ message: "Image is too large. Max size is 5MB." });
                }
                return res.status(400).send({ message: err.message || "Upload failed." });
            }
            return next(err);
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
