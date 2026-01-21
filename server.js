require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const multer = require("multer");
const rateLimit = require("express-rate-limit");
const mongoose = require("mongoose");
const fs = require("fs");

// ================= APP =================
const app = express();
const PORT = process.env.PORT || 3000;

// ================= SECURITY MIDDLEWARE =================
app.use(helmet());

app.use(cors({
  origin: "*", // later restrict to your domain
  methods: ["GET", "POST", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

// ================= RATE LIMIT (LOGIN) =================
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 10,
  message: { message: "Too many login attempts. Try later." }
});

// ================= DATABASE =================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("Mongo error:", err));

// ================= MODELS =================
const User = require("./models/User");
const Message = require("./models/Message");

// ================= JWT =================
const JWT_SECRET = process.env.JWT_SECRET;

// ================= AUTH MIDDLEWARE =================
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(403).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }
    req.user = decoded;
    next();
  });
}

// ================= FILE UPLOAD =================
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowed = [
      "image/jpeg",
      "image/png",
      "image/gif",
      "video/mp4",
      "video/webm"
    ];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error("File type not allowed"));
    }
    cb(null, true);
  }
});

app.use("/uploads", express.static("uploads"));

// ================= ROUTES =================

//LOGIN (DB-BASED, SECURE)
app.post("/api/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign(
    { id: user._id, username: user.username },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ token });
});

//PRIVATE CHECK
app.get("/api/private", verifyToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.username}` });
});

// UPLOAD MEDIA
app.post("/api/upload", verifyToken, upload.single("media"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: "No file uploaded" });
  }

  res.json({
    message: "File uploaded successfully",
    filename: req.file.filename
  });
});

//GET MEDIA
app.get("/api/media", verifyToken, (req, res) => {
  fs.readdir("uploads", (err, files) => {
    if (err) {
      return res.status(500).json({ message: "Failed to load media" });
    }
    res.json({ files });
  });
});

//DELETE MEDIA
app.delete("/api/delete/:filename", verifyToken, (req, res) => {
  const filePath = `uploads/${req.params.filename}`;

  fs.unlink(filePath, err => {
    if (err) {
      return res.status(404).json({ message: "File not found" });
    }
    res.json({ message: "File deleted successfully" });
  });
});

//SEND MESSAGE (DB)
app.post("/api/message", verifyToken, async (req, res) => {
  const { text } = req.body;
  if (!text) {
    return res.status(400).json({ message: "Message required" });
  }

  const to = req.user.username === "user1" ? "user2" : "user1";

  const msg = await Message.create({
    from: req.user.username,
    to,
    text
  });

  res.json(msg);
});

// GET MESSAGES (DB)
app.get("/api/messages", verifyToken, async (req, res) => {
  const user = req.user.username;

  const msgs = await Message.find({
    $or: [{ from: user }, { to: user }]
  }).sort({ createdAt: 1 });

  res.json({ messages: msgs });
});

app.post("/api/reset-password", verifyToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(req.user.id);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  const match = await bcrypt.compare(oldPassword, user.password);
  if (!match) {
    return res.status(401).json({ message: "Old password incorrect" });
  }

  const hashed = await bcrypt.hash(newPassword, 10);
  user.password = hashed;
  await user.save();

  res.json({ message: "Password changed successfully" });
});
// ================= START SERVER =================
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
