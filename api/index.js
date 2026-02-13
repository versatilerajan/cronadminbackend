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

app.use(helmet());
app.use(compression());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 400 }));
app.use(express.json({ limit: "100kb" }));
app.use(cors({
  origin: true,
  methods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
  optionsSuccessStatus: 204,
}));
app.options(/.*/, cors());

// ================= DB CONNECT =================
async function connectDB() {
  if (mongoose.connection.readyState >= 1) return;
  await mongoose.connect(process.env.MONGO_URI, {
    serverSelectionTimeoutMS: 15000,
    connectTimeoutMS: 15000,
  });
  console.log("MongoDB connected");
}

// ================= SCHEMAS =================
const testSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true, maxlength: 200 },
  date: { type: String, required: true, match: /^\d{4}-\d{2}-\d{2}$/ },
  startTime: Date,
  endTime: Date,
  totalQuestions: { type: Number, default: 0 },
  testType: {
    type: String,
    enum: ["paid", "free"],
    required: true
  },
  phase: { 
    type: String, 
    enum: ["daily", "gs", "csat", null], 
    default: null 
  },   // NEW FIELD
}, { timestamps: true });

const questionSchema = new mongoose.Schema({
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
  phase: { 
    type: String, 
    enum: ["GS", "CSAT"], 
    default: "GS" 
  },   // NEW FIELD - per question
}, { timestamps: true });

const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
});

const Test = mongoose.models.Test || mongoose.model("Test", testSchema);
const Question = mongoose.models.Question || mongoose.model("Question", questionSchema);
const Admin = mongoose.models.Admin || mongoose.model("Admin", adminSchema);

// ================= ADMIN AUTH =================
const adminAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, message: "No token" });
  }
  try {
    req.admin = jwt.verify(authHeader.split(" ")[1], process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: "Invalid/expired token" });
  }
};

// ================= ROUTES =================
app.get("/", async (req, res) => {
  try {
    await connectDB();
    res.json({ success: true, message: "Admin Backend Running" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/admin/login", async (req, res) => {
  try {
    await connectDB();
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: "Email & password required" });

    const admin = await Admin.findOne({ email: email.toLowerCase().trim() });
    if (!admin) return res.status(401).json({ success: false, message: "Admin not found" });

    if (!await bcrypt.compare(password, admin.password)) {
      return res.status(401).json({ success: false, message: "Wrong password" });
    }

    const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: "24h" });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/admin/create-test-with-questions", adminAuth, async (req, res) => {
  try {
    await connectDB();

    let { title, date, startTime, endTime, questions, testType } = req.body;

    if (!title?.trim() || !date || !Array.isArray(questions) || !["paid", "free"].includes(testType)) {
      return res.status(400).json({ 
        success: false, 
        message: "title, date, questions array, and testType ('paid' or 'free') are required" 
      });
    }

    const numQuestions = questions.length;

    // ─── UPDATED VALIDATION ───────────────────────────────────────
    let phase = null;
    let expectedCountMessage = "";

    if (numQuestions === 75) {
      phase = "daily";
      expectedCountMessage = "Daily test (Mon–Sat)";
    } else if (numQuestions === 100) {
      phase = "gs";
      expectedCountMessage = "GS Paper (Sunday Phase 1)";
    } else if (numQuestions === 80) {
      phase = "csat";
      expectedCountMessage = "CSAT Paper (Sunday Phase 2)";
    } else {
      return res.status(400).json({ 
        success: false, 
        message: "Allowed question counts: 75 (daily), 100 (GS paper), 80 (CSAT paper) only" 
      });
    }

    if (date.includes("T")) date = date.split("T")[0];
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ success: false, message: "Date must be YYYY-MM-DD" });
    }

    const dateObj = new Date(date + "T00:00:00+05:30");
    if (isNaN(dateObj.getTime())) {
      return res.status(400).json({ success: false, message: "Invalid date" });
    }

    const existing = await Test.findOne({ date, testType, phase });
    if (existing) {
      return res.status(409).json({
        success: false,
        message: `A ${testType} ${expectedCountMessage} already exists for date ${date}`
      });
    }

    const IST_OFFSET_MS = 5.5 * 60 * 60 * 1000;
    const start = startTime
      ? new Date(new Date(startTime).getTime() - IST_OFFSET_MS)
      : new Date(dateObj.getTime());
    const end = endTime
      ? new Date(new Date(endTime).getTime() - IST_OFFSET_MS)
      : new Date(start.getTime() + 24 * 60 * 60 * 1000 - 1000);

    const test = await Test.create({
      title: title.trim(),
      date,
      startTime: start,
      endTime: end,
      totalQuestions: numQuestions,
      testType,
      phase,                    // NEW: daily / gs / csat
    });

    // Automatically assign phase to each question
    const questionPhase = phase === "daily" ? "GS" : phase === "gs" ? "GS" : "CSAT";

    const qDocs = questions.map((q, idx) => ({
      testId: test._id,
      questionNumber: q.questionNumber || (idx + 1),
      questionStatement: String(q.questionStatement || "").trim(),
      options: {
        option1: String(q.options?.option1 || "").trim(),
        option2: String(q.options?.option2 || "").trim(),
        option3: String(q.options?.option3 || "").trim(),
        option4: String(q.options?.option4 || "").trim(),
      },
      correctOption: q.correctOption,
      phase: questionPhase           // NEW: GS or CSAT per question
    }));

    await Question.insertMany(qDocs);

    const typeDisplay = testType.toUpperCase();
    const phaseDisplay = phase === "daily" ? "Daily" : phase.toUpperCase();

    res.json({
      success: true,
      message: `${typeDisplay} ${phaseDisplay} test created successfully (${numQuestions} questions)`,
      testId: test._id.toString(),
      date,
      totalQuestions: numQuestions,
      testType,
      phase,
      startTimeIST: new Date(start.getTime() + IST_OFFSET_MS).toISOString(),
      endTimeIST: new Date(end.getTime() + IST_OFFSET_MS).toISOString(),
    });
  } catch (err) {
    console.error("Create test error:", err.message, err.stack);
    res.status(500).json({ success: false, message: err.message || "Creation failed" });
  }
});

app.get("/admin/tests", adminAuth, async (req, res) => {
  try {
    await connectDB();
    const tests = await Test.find().sort({ date: -1 }).lean();

    const IST_OFFSET_MS = 5.5 * 60 * 60 * 1000;
    const testsWithIST = tests.map(t => ({
      ...t,
      startTimeIST: t.startTime ? new Date(t.startTime.getTime() + IST_OFFSET_MS).toISOString() : null,
      endTimeIST: t.endTime ? new Date(t.endTime.getTime() + IST_OFFSET_MS).toISOString() : null,
      phaseDisplay: t.phase === "daily" ? "Daily (75)" :
                    t.phase === "gs"    ? "GS Paper (100)" :
                    t.phase === "csat"  ? "CSAT Paper (80)" : "—"
    }));

    res.json({ success: true, tests: testsWithIST });
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
    res.json({ success: true, message: "Test & questions deleted" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Delete failed" });
  }
});

module.exports = app;
