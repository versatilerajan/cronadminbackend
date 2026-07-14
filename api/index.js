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
app.use(express.json({ limit: "2mb" }));

app.use(cors({
  origin: true,
  methods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
  optionsSuccessStatus: 204,
}));

app.options(/.*/, cors());

const userConn = mongoose.createConnection(process.env.MONGO_URI, {
  serverSelectionTimeoutMS: 15000,
  connectTimeoutMS: 15000,
});
const questionConn = mongoose.createConnection(process.env.QUESTIONDB_URI, {
  serverSelectionTimeoutMS: 15000,
  connectTimeoutMS: 15000,
});
const freePcsConn = mongoose.createConnection(process.env.FREEPCS_URI, {
  serverSelectionTimeoutMS: 15000,
  connectTimeoutMS: 15000,
});

userConn.on("connected", () => console.log("userDB (MONGO_URI) connected"));
userConn.on("error", (err) => console.error("userDB connection error:", err));

questionConn.on("connected", () => console.log("questionsDB (QUESTIONDB_URI) connected"));
questionConn.on("error", (err) => console.error("questionsDB connection error:", err));

freePcsConn.on("connected", () => console.log("freePcsDB (FREEPCS_URI) connected"));
freePcsConn.on("error", (err) => console.error("freePcsDB connection error:", err));

async function connectDB() {
  await Promise.all([userConn.asPromise(), questionConn.asPromise(), freePcsConn.asPromise()]);
}

connectDB().catch(err => console.error("Initial DB connect failed:", err));

const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
});

const resultSchema = new mongoose.Schema({
  userId: String,
  testId: mongoose.Schema.Types.ObjectId,
  phase: String,
  score: Number,
  correct: Number,
  incorrect: Number,
  unattempted: Number,
  attempted: Number,
  totalQuestions: Number,
  submittedAt: Date,
  startedAt: Date,
  isLate: Boolean,
  answers: Array,
  timeTakenSeconds: Number,
}, { timestamps: true });

const freeResultSchema = new mongoose.Schema({
  testId: mongoose.Schema.Types.ObjectId,
  score: Number,
  totalQuestions: Number,
  submittedAt: { type: Date, default: Date.now },
}, { timestamps: true });

const testSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true, maxlength: 200 },
  date: { type: String, required: true, match: /^\d{4}-\d{2}-\d{2}$/ },
  startTime: { type: Date },
  endTime: { type: Date },
  totalQuestions: { type: Number, default: 0 },
  testType: { type: String, enum: ["paid", "free"], required: true },
  phase: { type: String, enum: ["daily", "gs", "csat", "free pcs", null], default: null },
}, { timestamps: true });

const questionSchema = new mongoose.Schema({
  testId: { type: mongoose.Schema.Types.ObjectId, ref: "Test", required: true },
  imageUrl: { type: String, trim: true, default: null },
  english: {
    question: { type: String, required: true, trim: true },
    options: { type: Object, required: true },
    english_explanation: { type: String, trim: true, default: "" },
  },
  hindi: {
    question: { type: String, required: true, trim: true },
    options: { type: Object, required: true },
    hindi_explanation: { type: String, trim: true, default: "" },
  },
  marks: { type: Number, default: 2 },
  negativeMarks: { type: Number, default: 0.66 },
  correct_answer: { type: Number, required: true },
  phase: { type: String, enum: ["GS", "CSAT"], default: "GS" },
}, { timestamps: true });

const freePCSQuestionSchema = new mongoose.Schema({
  testId: { type: mongoose.Schema.Types.ObjectId, ref: "Test", required: true },
  title: { type: String, required: true, trim: true, maxlength: 200 },
  examType: { type: String, required: true, trim: true },
  year: { type: Number, required: true },
  imageUrl: { type: String, trim: true, default: null },
  english: {
    question: { type: String, required: true, trim: true },
    options: { type: Object, required: true },
    english_explanation: { type: String, trim: true, default: "" },
  },
  hindi: {
    question: { type: String, required: true, trim: true },
    options: { type: Object, required: true },
    hindi_explanation: { type: String, trim: true, default: "" },
  },
  marks: { type: Number, default: 2 },
  negativeMarks: { type: Number, default: 0.66 },
  correct_answer: { type: Number, required: true },
  phase: { type: String, enum: ["free pcs"], default: "free pcs" },
}, { timestamps: true });

const Admin      = userConn.models.Admin      || userConn.model("Admin", adminSchema);
const Result     = userConn.models.Result     || userConn.model("Result", resultSchema);
const FreeResult = userConn.models.FreeResult || userConn.model("FreeResult", freeResultSchema);

const Test     = questionConn.models.Test     || questionConn.model("Test", testSchema);
const Question = questionConn.models.Question || questionConn.model("Question", questionSchema);

const FreePCSQuestion = freePcsConn.models.FreePCSQuestion || freePcsConn.model("FreePCSQuestion", freePCSQuestionSchema);

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

function makeDateUTC(dateStr, timeStr) {
  return new Date(`${dateStr}T${timeStr}+05:30`);
}

function validateQuestionPayload(q, idx) {
  const errors = [];
  const label = `Question ${idx + 1}`;

  const isPlainObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);

  if (!q.english || typeof q.english.question !== "string" || !q.english.question.trim()) {
    errors.push(`${label}: english.question is required`);
  }
  if (!q.english || !isPlainObject(q.english.options) || Object.keys(q.english.options).length < 2) {
    errors.push(`${label}: english.options must be an object with at least 2 options`);
  }

  if (!q.hindi || typeof q.hindi.question !== "string" || !q.hindi.question.trim()) {
    errors.push(`${label}: hindi.question is required`);
  }
  if (!q.hindi || !isPlainObject(q.hindi.options) || Object.keys(q.hindi.options).length < 2) {
    errors.push(`${label}: hindi.options must be an object with at least 2 options`);
  }

  if (q.correct_answer === undefined || q.correct_answer === null || isNaN(Number(q.correct_answer))) {
    errors.push(`${label}: correct_answer (number) is required`);
  }

  return errors;
}

app.get("/", async (req, res) => {
  try {
    await connectDB();
    const nowIST = new Date(Date.now() + 5.5 * 60 * 60 * 1000);
    res.json({
      success: true,
      message: "Admin Backend Running",
      currentISTTime: nowIST.toISOString().replace("Z", "+05:30"),
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/admin/login", async (req, res) => {
  try {
    await connectDB();
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, message: "Email & password required" });

    const admin = await Admin.findOne({ email: email.toLowerCase().trim() });
    if (!admin)
      return res.status(401).json({ success: false, message: "Admin not found" });

    if (!await bcrypt.compare(password, admin.password))
      return res.status(401).json({ success: false, message: "Wrong password" });

    const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: "24h" });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/admin/create-test-with-questions", adminAuth, async (req, res) => {
  try {
    await connectDB();

    let { title, date, questions, testType } = req.body;

    if (!title?.trim() || !date || !Array.isArray(questions) || !["paid", "free"].includes(testType)) {
      return res.status(400).json({
        success: false,
        message: "title, date, questions array, and testType ('paid' or 'free') are required",
      });
    }

    const numQuestions = questions.length;

    let phase = null;
    if      (numQuestions === 75)  phase = "daily";
    else if (numQuestions === 100) phase = "gs";
    else if (numQuestions === 80)  phase = "csat";
    else {
      return res.status(400).json({
        success: false,
        message: "Allowed question counts: 75 (daily Mon-Sat), 100 (GS Sunday), 80 (CSAT Sunday) only",
      });
    }

    const payloadErrors = questions.flatMap((q, idx) => validateQuestionPayload(q, idx));
    if (payloadErrors.length) {
      return res.status(400).json({
        success: false,
        message: "Invalid questions payload",
        errors: payloadErrors,
      });
    }

    if (date.includes("T")) date = date.split("T")[0];
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ success: false, message: "Date must be in YYYY-MM-DD format" });
    }

    const startTimeUTC = makeDateUTC(date, "00:00:00.000");
    const endTimeUTC   = makeDateUTC(date, "23:59:59.999");

    if (isNaN(startTimeUTC.getTime()) || isNaN(endTimeUTC.getTime())) {
      return res.status(400).json({ success: false, message: "Invalid date — could not compute timestamps" });
    }

    console.log("Creating test window:", {
      date,
      phase,
      startUTC: startTimeUTC.toISOString(),
      endUTC:   endTimeUTC.toISOString(),
      startIST: `${date}T00:00:00+05:30`,
      endIST:   `${date}T23:59:59+05:30`,
    });

    const test = await Test.create({
      title: title.trim(),
      date,
      startTime: startTimeUTC,
      endTime:   endTimeUTC,
      totalQuestions: numQuestions,
      testType,
      phase,
    });

    const questionPhase = (phase === "csat") ? "CSAT" : "GS";

    const qDocs = questions.map((q) => ({
      testId: test._id,
      imageUrl: q.imageUrl ? String(q.imageUrl).trim() : null,
      english: {
        question: String(q.english.question).trim(),
        options: q.english.options,
        english_explanation: String(q.english.english_explanation || "").trim(),
      },
      hindi: {
        question: String(q.hindi.question).trim(),
        options: q.hindi.options,
        hindi_explanation: String(q.hindi.hindi_explanation || "").trim(),
      },
      marks: 2,
      negativeMarks: 0.66,
      correct_answer: Number(q.correct_answer),
      phase: questionPhase,
    }));

    await Question.insertMany(qDocs);

    const phaseDisplay =
      phase === "daily" ? "Daily (75 Q)" :
      phase === "gs"    ? "GS Paper (100 Q)" :
                          "CSAT Paper (80 Q)";

    res.json({
      success: true,
      message: `${testType.toUpperCase()} ${phaseDisplay} test created on ${date}`,
      testId:         test._id.toString(),
      date,
      totalQuestions: numQuestions,
      testType,
      phase,
      startTimeIST: `${date}T00:00:00+05:30`,
      endTimeIST:   `${date}T23:59:59+05:30`,
    });
  } catch (err) {
    console.error("Create test error:", err);
    res.status(500).json({ success: false, message: err.message || "Creation failed" });
  }
});

app.post("/admin/create-free-pcs-test", adminAuth, async (req, res) => {
  try {
    await connectDB();

    let { title, date, examType, year, questions } = req.body;

    if (!title?.trim() || !date || !examType?.trim() || !year || !Array.isArray(questions) || questions.length === 0) {
      return res.status(400).json({
        success: false,
        message: "title, date, examType, year, and a non-empty questions array are required",
      });
    }

    const yearNum = Number(year);
    if (isNaN(yearNum)) {
      return res.status(400).json({ success: false, message: "year must be a number" });
    }

    const payloadErrors = questions.flatMap((q, idx) => validateQuestionPayload(q, idx));
    if (payloadErrors.length) {
      return res.status(400).json({
        success: false,
        message: "Invalid questions payload",
        errors: payloadErrors,
      });
    }

    if (date.includes("T")) date = date.split("T")[0];
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ success: false, message: "Date must be in YYYY-MM-DD format" });
    }

    const trimmedTitle = title.trim();

    const test = await Test.create({
      title: trimmedTitle,
      date,
      totalQuestions: questions.length,
      testType: "free",
      phase: "free pcs",
    });

    const qDocs = questions.map((q) => ({
      testId: test._id,
      title: trimmedTitle,
      examType: examType.trim(),
      year: yearNum,
      imageUrl: q.imageUrl ? String(q.imageUrl).trim() : null,
      english: {
        question: String(q.english.question).trim(),
        options: q.english.options,
        english_explanation: String(q.english.english_explanation || "").trim(),
      },
      hindi: {
        question: String(q.hindi.question).trim(),
        options: q.hindi.options,
        hindi_explanation: String(q.hindi.hindi_explanation || "").trim(),
      },
      marks: 2,
      negativeMarks: 0.66,
      correct_answer: Number(q.correct_answer),
      phase: "free pcs",
    }));

    await FreePCSQuestion.insertMany(qDocs);

    res.json({
      success: true,
      message: `Free PCS test created for ${examType.trim()} ${yearNum}`,
      testId: test._id.toString(),
      title: trimmedTitle,
      date,
      examType: examType.trim(),
      year: yearNum,
      totalQuestions: questions.length,
      testType: "free",
      phase: "free pcs",
      availability: "No expiry — this test stays available until an admin deletes it",
    });
  } catch (err) {
    console.error("Create free PCS test error:", err);
    res.status(500).json({ success: false, message: err.message || "Creation failed" });
  }
});

app.get("/admin/tests", adminAuth, async (req, res) => {
  try {
    await connectDB();
    const tests = await Test.find().sort({ date: -1, phase: 1 }).lean();

    const testsWithIST = tests.map(t => {
      const toIST = (d) => {
        if (!d) return null;
        const shifted = new Date(d.getTime() + 5.5 * 60 * 60 * 1000);
        return shifted.toISOString().replace("Z", "+05:30");
      };
      return {
        ...t,
        startTimeIST: toIST(t.startTime),
        endTimeIST:   toIST(t.endTime),
        phaseDisplay:
          t.phase === "daily"    ? "Daily (75q)" :
          t.phase === "gs"       ? "GS Paper (100q)" :
          t.phase === "csat"     ? "CSAT Paper (80q)" :
          t.phase === "free pcs" ? "Free PCS" : "Unknown",
      };
    });

    res.json({ success: true, tests: testsWithIST });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to load tests" });
  }
});

app.get("/admin/free-pcs-questions/:testId", adminAuth, async (req, res) => {
  try {
    await connectDB();
    const { testId } = req.params;
    const questions = await FreePCSQuestion.find({ testId }).sort({ createdAt: 1 }).lean();
    res.json({ success: true, count: questions.length, questions });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to load free PCS questions" });
  }
});

app.delete("/admin/delete-test/:testId", adminAuth, async (req, res) => {
  try {
    await connectDB();

    const testId = req.params.testId;

    const test = await Test.findById(testId);
    if (!test) {
      return res.status(404).json({ success: false, message: "Test not found" });
    }

    const qResult  = await Question.deleteMany({ testId });
    const pResult  = await FreePCSQuestion.deleteMany({ testId });
    const rResult  = await Result.deleteMany({ testId });
    const frResult = await FreeResult.deleteMany({ testId });

    await Test.findByIdAndDelete(testId);

    console.log(`Deleted test ${testId}:`, {
      questions: qResult.deletedCount,
      freePcsQuestions: pResult.deletedCount,
      results: rResult.deletedCount,
      freeResults: frResult.deletedCount,
    });

    res.json({
      success: true,
      message: "Test, questions, and all user results deleted successfully",
      deleted: {
        questions:        qResult.deletedCount,
        freePcsQuestions: pResult.deletedCount,
        results:          rResult.deletedCount,
        freeResults:      frResult.deletedCount,
      },
    });
  } catch (err) {
    console.error("Delete test error:", err);
    res.status(500).json({ success: false, message: "Delete failed" });
  }
});

module.exports = app;
