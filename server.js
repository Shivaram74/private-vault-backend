const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const fs = require("fs");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ ensure uploads folder exists
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// ✅ middleware
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());
app.use("/uploads", express.static("uploads"));

// ================= AUTH =================
const JWT_SECRET = "private_vault_secret";

const users = [
  { id: 1, username: "user1", password: "" },
  { id: 2, username: "user2", password: "" }
];

(async () => {
  users[0].password = await bcrypt.hash("ShivD@726", 10);
  users[1].password = await bcrypt.hash("password2", 10);
})();

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(403).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token" });
    }
    req.user = decoded;
    next();
  });
}

// ================= MULTER =================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
});
const upload = multer({ storage });

// ================= ROUTES =================
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ token });
});

app.get("/api/private", verifyToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.username}` });
});

app.post("/api/upload", verifyToken, upload.single("media"), (req, res) => {
  if (!req.file) return res.status(400).json({ message: "No file uploaded" });

  console.log("FILE RECEIVED:", req.file.filename);
  res.json({ message: "File uploaded successfully", filename: req.file.filename });
});

app.get("/api/media", verifyToken, (req, res) => {
  fs.readdir("uploads", (err, files) => {
    if (err) return res.status(500).json({ message: "Failed to load media" });
    res.json({ files });
  });
});

app.delete("/api/delete/:filename", verifyToken, (req, res) => {
  const filePath = `uploads/${req.params.filename}`;

  fs.unlink(filePath, err => {
    if (err) return res.status(404).json({ message: "File not found" });
    res.json({ message: "File deleted successfully" });
  });
});

app.listen(PORT, () => console.log("Server running on port", PORT));
