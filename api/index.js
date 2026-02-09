require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();

// Middleware
app.use(helmet());
app.use(compression());
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 400,
    standardHeaders: true,
    legacyHeaders: false,
  })
);
app.use(express.json({ limit: "100kb" }));

// CORS – allow all origins for now (tighten later if needed)
app.use(
  cors({
    origin: true,
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
    optionsSuccessStatus: 204,
  })
);

// FIX: Use regex wildcard instead of bare "*" (Express 5 requirement)
app.options(/.*/, cors());

// ─── DB connect helper ─────────────────────────────────────────
async function connectDB() {
  if (mongoose.connection.readyState >= 1) return;

  try {
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 15000,
      connectTimeoutMS: 15000,
    });
    console.log("MongoDB connected");
  } catch (err) {
    console.error("MongoDB connect failed:", err.message);
    throw err;
  }
}

// ─── Schemas ───────────────────────────────────────────────────
const testSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true, maxlength: 200 },
    date: { type: String, required: true, match: /^\d{4}-\d{2}-\d{2}$/ },
    startTime: Date,
    endTime: Date,
    isActive: { type: Boolean, default: false },
    totalQuestions: { type: Number, default: 0 },
  },
  { timestamps: true }
);

const questionSchema = new mongoose.Schema(
  {
    testId: { type: mongoose.Schema.Types.ObjectId, ref: "Test", required: true },
    questionNumber: { type: Number, required: true, min: 1 },
    questionStatement: { type: String, required: true, trim: true },
    options: {
      option1: { type: String, required: true, trim: true },
      option2: { type: String, required: true, trim: true },
      option3: { type: String, required: true, trim: true },
      option4: { type: String, required: true, trim: true },
    },
    correctOption: {
      type: String,
      enum: ["option1", "option2", "option3", "option4"],
      required: true,
    },
  },
  { timestamps: true }
);

const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
});

const Test = mongoose.models.Test || mongoose.model("Test", testSchema);
const Question = mongoose.models.Question || mongoose.model("Question", questionSchema);
const Admin = mongoose.models.Admin || mongoose.model("Admin", adminSchema);

// ─── Auth middleware ───────────────────────────────────────────
const adminAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, message: "No token provided" });
  }
  const token = authHeader.split(" ")[1];
  try {
    req.admin = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: "Invalid/expired token" });
  }
};

// ─── Routes ────────────────────────────────────────────────────
app.get("/", async (req, res) => {
  try {
    await connectDB();
    res.json({ success: true, message: "Backend running", dbReady: true });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error", detail: err.message });
  }
});

app.post("/admin/login", async (req, res) => {
  try {
    await connectDB();
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: "Email & password required" });

    const admin = await Admin.findOne({ email: email.toLowerCase().trim() });
    if (!admin) return res.status(401).json({ success: false, message: "Admin not found" });

    const match = await bcrypt.compare(password, admin.password);
    if (!match) return res.status(401).json({ success: false, message: "Wrong password" });

    const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: "24h" });
    res.json({ success: true, token });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/admin/create-test-with-questions", adminAuth, async (req, res) => {
  try {
    await connectDB();
    const { title, date, startTime, endTime, questions } = req.body;

    if (!title?.trim() || !date || !Array.isArray(questions) || questions.length !== 50) {
      return res.status(400).json({ success: false, message: "Need title, date & exactly 50 questions" });
    }

    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ success: false, message: "Date must be YYYY-MM-DD" });
    }

    const existing = await Test.findOne({ date });
    if (existing) return res.status(409).json({ success: false, message: "Test exists for this date" });

    const test = await Test.create({
      title: title.trim(),
      date,
      startTime: startTime ? new Date(startTime) : undefined,
      endTime: endTime ? new Date(endTime) : undefined,
      totalQuestions: 50,
    });

    const qDocs = questions.map((q, idx) => ({
      testId: test._id,
      questionNumber: q.questionNumber || idx + 1,
      questionStatement: String(q.questionStatement || "").trim(),
      options: {
        option1: String(q.options?.option1 || "").trim(),
        option2: String(q.options?.option2 || "").trim(),
        option3: String(q.options?.option3 || "").trim(),
        option4: String(q.options?.option4 || "").trim(),
      },
      correctOption: q.correctOption,
    }));

    await Question.insertMany(qDocs);

    res.json({ success: true, message: "Test + questions created", testId: test._id.toString() });
  } catch (err) {
    console.error("Create test error:", err.message);
    res.status(500).json({ success: false, message: err.message || "Creation failed" });
  }
});

app.get("/admin/tests", adminAuth, async (req, res) => {
  try {
    await connectDB();
    const tests = await Test.find().sort({ date: -1 }).lean();
    res.json({ success: true, tests });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to load tests" });
  }
});

app.delete("/admin/delete-test/:testId", adminAuth, async (req, res) => {
  try {
    await connectDB();
    await Question.deleteMany({ testId: req.params.testId });
    const result = await Test.findByIdAndDelete(req.params.testId);
    if (!result) return res.status(404).json({ success: false, message: "Test not found" });
    res.json({ success: true, message: "Test deleted" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Delete failed" });
  }
});

module.exports = app;
