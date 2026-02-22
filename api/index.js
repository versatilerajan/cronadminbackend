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

connectDB().catch(err => console.error("Initial DB connect failed:", err));

// ================= SCHEMAS =================
const testSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true, maxlength: 200 },
  date: { type: String, required: true, match: /^\d{4}-\d{2}-\d{2}$/ },
  startTime: { type: Date },
  endTime: { type: Date },
  totalQuestions: { type: Number, default: 0 },
  testType: { type: String, enum: ["paid", "free"], required: true },
  phase: { type: String, enum: ["daily", "gs", "csat", null], default: null },
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
  phase: { type: String, enum: ["GS", "CSAT"], default: "GS" },
}, { timestamps: true });

const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
});

// Result schema — mirrors user backend so we can cascade-delete
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

const Test       = mongoose.models.Test       || mongoose.model("Test",       testSchema);
const Question   = mongoose.models.Question   || mongoose.model("Question",   questionSchema);
const Admin      = mongoose.models.Admin      || mongoose.model("Admin",      adminSchema);
const Result     = mongoose.models.Result     || mongoose.model("Result",     resultSchema);
const FreeResult = mongoose.models.FreeResult || mongoose.model("FreeResult", freeResultSchema);

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

// ================= IST HELPER =================
//
// KEY RULE: When you construct a Date with an explicit timezone offset like
// "+05:30", JavaScript already stores the correct UTC value internally.
// You must NOT subtract IST_OFFSET_MS again — that would double-subtract
// 5.5 hours and make the stored UTC time wrong by 11 hours.
//
// Correct pattern:
//   new Date("2024-01-15T00:00:00.000+05:30")
//   → internally stored as 2024-01-14T18:30:00.000Z  (correct UTC)
//   → when user backend adds +5:30 for display: 00:00 IST  ✓
//
// Wrong pattern (old code bug):
//   const ist = new Date("2024-01-15T00:00:00.000+05:30");  // already UTC
//   const utc = new Date(ist.getTime() - IST_OFFSET_MS);     // double-subtracts!
//   → stored as 2024-01-14T13:00:00.000Z  (wrong by -5.5h)
//   → when user backend adds +5:30 for display: 18:30 IST = 6:30 PM  ✗

function makeDateUTC(dateStr, timeStr) {
  // dateStr: "YYYY-MM-DD"
  // timeStr: "HH:MM:SS"
  // Returns a JS Date whose UTC value correctly represents that IST wall-clock.
  // Using the +05:30 literal lets the JS engine handle conversion without
  // any manual arithmetic — preventing the double-offset bug.
  return new Date(`${dateStr}T${timeStr}+05:30`);
}

// ================= ROUTES =================
app.get("/", async (req, res) => {
  try {
    await connectDB();
    // Show current IST time for sanity-checking in Vercel logs
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

    if (date.includes("T")) date = date.split("T")[0];
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ success: false, message: "Date must be in YYYY-MM-DD format" });
    }

    // ─── Build correct UTC timestamps ──────────────────────────────────────────
    //
    // We use the "+05:30" literal in the ISO string so JavaScript handles
    // IST→UTC conversion automatically. No manual arithmetic needed.
    //
    // startTime: 00:00:00 IST  =  18:30:00 UTC previous day
    // endTime:   23:59:59 IST  =  18:29:59 UTC same day
    //
    const startTimeUTC = makeDateUTC(date, "00:00:00.000"); // 00:00:00 IST
    const endTimeUTC   = makeDateUTC(date, "23:59:59.999"); // 23:59:59 IST

    // Verify the values are sane before saving
    if (isNaN(startTimeUTC.getTime()) || isNaN(endTimeUTC.getTime())) {
      return res.status(400).json({ success: false, message: "Invalid date — could not compute timestamps" });
    }

    // Debug log — visible in Vercel function logs
    console.log("Creating test window:", {
      date,
      phase,
      startUTC: startTimeUTC.toISOString(),   // e.g. "2024-01-14T18:30:00.000Z"
      endUTC:   endTimeUTC.toISOString(),      // e.g. "2024-01-15T18:29:59.999Z"
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
      // Return explicit +05:30 strings so callers always see correct IST
      startTimeIST: `${date}T00:00:00+05:30`,
      endTimeIST:   `${date}T23:59:59+05:30`,
    });
  } catch (err) {
    console.error("Create test error:", err);
    res.status(500).json({ success: false, message: err.message || "Creation failed" });
  }
});

app.get("/admin/tests", adminAuth, async (req, res) => {
  try {
    await connectDB();
    const tests = await Test.find().sort({ date: -1, phase: 1 }).lean();

    const testsWithIST = tests.map(t => {
      // Build explicit +05:30 strings from the stored UTC dates
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
          t.phase === "daily" ? "Daily (75q)" :
          t.phase === "gs"    ? "GS Paper (100q)" :
          t.phase === "csat"  ? "CSAT Paper (80q)" : "Unknown",
      };
    });

    res.json({ success: true, tests: testsWithIST });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to load tests" });
  }
});

// ── DELETE TEST: cascade-deletes questions + all user results ─────────────────
// This ensures the archive tab in the Flutter app no longer shows the deleted
// test's attempts, and the results don't pollute rankings.
app.delete("/admin/delete-test/:testId", adminAuth, async (req, res) => {
  try {
    await connectDB();

    const testId = req.params.testId;

    // 1. Verify test exists
    const test = await Test.findById(testId);
    if (!test) {
      return res.status(404).json({ success: false, message: "Test not found" });
    }

    // 2. Delete questions for this test
    const qResult = await Question.deleteMany({ testId });

    // 3. Delete all paid user results for this test (paid tests use Result)
    const rResult = await Result.deleteMany({ testId });

    // 4. Delete free test results if applicable
    const frResult = await FreeResult.deleteMany({ testId });

    // 5. Delete the test itself
    await Test.findByIdAndDelete(testId);

    console.log(`Deleted test ${testId}:`, {
      questions: qResult.deletedCount,
      results: rResult.deletedCount,
      freeResults: frResult.deletedCount,
    });

    res.json({
      success: true,
      message: "Test, questions, and all user results deleted successfully",
      deleted: {
        questions:   qResult.deletedCount,
        results:     rResult.deletedCount,
        freeResults: frResult.deletedCount,
      },
    });
  } catch (err) {
    console.error("Delete test error:", err);
    res.status(500).json({ success: false, message: "Delete failed" });
  }
});

module.exports = app;
