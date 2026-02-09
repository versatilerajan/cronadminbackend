// api/index.js
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

app.use(
  cors({
    origin: true, // allow all for now – tighten later
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
    optionsSuccessStatus: 204,
  })
);

app.options("*", cors());

// ─── Helper: Connect to MongoDB (called per request) ───────────
async function connectDB() {
  if (mongoose.connection.readyState >= 1) return; // already connected

  try {
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 15000,
      connectTimeoutMS: 15000,
      maxPoolSize: 10,
    });
    console.log("MongoDB connected");
  } catch (err) {
    console.error("MongoDB connection failed:", err.message);
    throw err; // let route handle the error
  }
}

// ─── Schemas (same as before) ──────────────────────────────────
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
    return res.status(401).json({ success: false, message: "No token" });
  }
  const token = authHeader.split(" ")[1];
  try {
    req.admin = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ success: false, message: "Invalid token" });
  }
};

// ─── Routes ────────────────────────────────────────────────────
app.get("/", async (req, res) => {
  try {
    await connectDB();
    res.json({ success: true, message: "Admin backend running", dbState: mongoose.connection.readyState });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error", error: err.message });
  }
});

app.post("/admin/login", async (req, res) => {
  try {
    await connectDB();
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: "Email & password required" });

    const admin = await Admin.findOne({ email: email.toLowerCase() });
    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

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

    if (!title || !date || !Array.isArray(questions) || questions.length !== 50) {
      return res.status(400).json({ success: false, message: "Invalid input: need title, date & exactly 50 questions" });
    }

    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ success: false, message: "Date format must be YYYY-MM-DD" });
    }

    const exists = await Test.findOne({ date });
    if (exists) return res.status(409).json({ success: false, message: "Test already exists for this date" });

    const test = await Test.create({
      title: title.trim(),
      date,
      startTime: startTime ? new Date(startTime) : undefined,
      endTime: endTime ? new Date(endTime) : undefined,
      totalQuestions: 50,
    });

    const questionDocs = questions.map((q, i) => ({
      testId: test._id,
      questionNumber: q.questionNumber || i + 1,
      questionStatement: q.questionStatement?.trim() || "",
      options: {
        option1: q.options?.option1?.trim() || "",
        option2: q.options?.option2?.trim() || "",
        option3: q.options?.option3?.trim() || "",
        option4: q.options?.option4?.trim() || "",
      },
      correctOption: q.correctOption,
    }));

    await Question.insertMany(questionDocs);

    res.json({ success: true, message: "Test created with 50 questions", testId: test._id });
  } catch (err) {
    console.error("Create test error:", err.message);
    res.status(500).json({ success: false, message: err.message || "Failed to create test" });
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
    await Test.findByIdAndDelete(req.params.testId);
    res.json({ success: true, message: "Deleted" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Delete failed" });
  }
});

// Export for Vercel
module.exports = app;
