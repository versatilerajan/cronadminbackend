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
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
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
userConn.on("error", (err) => console.error("userDB connection error:", err.message));

questionConn.on("connected", () => console.log("questionsDB (QUESTIONDB_URI) connected"));
questionConn.on("error", (err) => console.error("questionsDB connection error:", err.message));

freePcsConn.on("connected", () => console.log("freePcsDB (FREEPCS_URI) connected"));
freePcsConn.on("error", (err) => console.error("freePcsDB connection error:", err.message));

async function connectUserDB() {
  await userConn.asPromise();
}
async function connectQuestionDB() {
  await questionConn.asPromise();
}
async function connectFreePcsDB() {
  await freePcsConn.asPromise();
}
async function connectDB() {
  return Promise.allSettled([
    userConn.asPromise(),
    questionConn.asPromise(),
    freePcsConn.asPromise(),
  ]);
}

userConn.asPromise().catch(err => console.error("Initial userDB connect failed:", err.message));
questionConn.asPromise().catch(err => console.error("Initial questionDB connect failed:", err.message));
freePcsConn.asPromise().catch(err => console.error("Initial freePcsDB connect failed:", err.message));

if (!process.env.MONGO_URI) console.error("MONGO_URI env var is missing");
if (!process.env.QUESTIONDB_URI) console.error("QUESTIONDB_URI env var is missing");
if (!process.env.FREEPCS_URI) console.error("FREEPCS_URI env var is missing");
if (!process.env.JWT_SECRET) console.error("JWT_SECRET env var is missing");

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
  collectionName: { type: String, default: null },
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

const PERSISTENCE_NOTE = "No expiry — this test stays available to users until an admin deletes it";

function slugify(title) {
  return title
    .toString()
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 50) || "test";
}

function getFreePCSModel(collectionName) {
  return freePcsConn.models[collectionName] ||
    freePcsConn.model(collectionName, freePCSQuestionSchema, collectionName);
}

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
  const results = await connectDB();
  const [userR, questionR, freePcsR] = results;
  res.json({
    success: true,
    message: "Admin Backend Running",
    currentISTTime: new Date(Date.now() + 5.5 * 60 * 60 * 1000).toISOString().replace("Z", "+05:30"),
    db: {
      userDB: userR.status,
      questionDB: questionR.status,
      freePcsDB: freePcsR.status,
    },
  });
});

app.post("/admin/login", async (req, res) => {
  try {
    await connectUserDB();
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, message: "Email & password required" });

    const admin = await Admin.findOne({ email: email.toLowerCase().trim() });
    if (!admin)
      return res.status(401).json({ success: false, message: "Admin not found" });

    if (!admin.password || !await bcrypt.compare(password, admin.password))
      return res.status(401).json({ success: false, message: "Wrong password" });

    if (!process.env.JWT_SECRET) {
      console.error("Admin login error: JWT_SECRET env var is missing");
      return res.status(500).json({ success: false, message: "Server misconfigured" });
    }

    const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: "24h" });
    res.json({ success: true, token });
  } catch (err) {
    console.error("Admin login error:", err.message, err.stack);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/admin/create-test-with-questions", adminAuth, async (req, res) => {
  try {
    await connectQuestionDB();

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
      availability: PERSISTENCE_NOTE,
    });
  } catch (err) {
    console.error("Create test error:", err);
    res.status(500).json({ success: false, message: err.message || "Creation failed" });
  }
});

app.post("/admin/create-free-pcs-test", adminAuth, async (req, res) => {
  try {
    await Promise.all([connectQuestionDB(), connectFreePcsDB()]);

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

    const collectionName = `fpcs_${slugify(trimmedTitle)}_${test._id.toString().slice(-6)}`;
    test.collectionName = collectionName;
    await test.save();

    const FreePCSQuestionDyn = getFreePCSModel(collectionName);

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

    await FreePCSQuestionDyn.insertMany(qDocs);

    res.json({
      success: true,
      message: `Free PCS test created for ${examType.trim()} ${yearNum}`,
      testId: test._id.toString(),
      collectionName,
      title: trimmedTitle,
      date,
      examType: examType.trim(),
      year: yearNum,
      totalQuestions: questions.length,
      testType: "free",
      phase: "free pcs",
      availability: PERSISTENCE_NOTE,
    });
  } catch (err) {
    console.error("Create free PCS test error:", err);
    res.status(500).json({ success: false, message: err.message || "Creation failed" });
  }
});

app.get("/admin/tests", adminAuth, async (req, res) => {
  try {
    await connectQuestionDB();
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
        availability: PERSISTENCE_NOTE,
      };
    });

    res.json({ success: true, tests: testsWithIST });
  } catch (err) {
    console.error("Load tests error:", err);
    res.status(500).json({ success: false, message: "Failed to load tests" });
  }
});

app.get("/admin/free-pcs-questions/:testId", adminAuth, async (req, res) => {
  try {
    await Promise.all([connectQuestionDB(), connectFreePcsDB()]);
    const { testId } = req.params;

    const test = await Test.findById(testId).lean();
    if (!test) {
      return res.status(404).json({ success: false, message: "Test not found" });
    }

    const Model = test.collectionName ? getFreePCSModel(test.collectionName) : FreePCSQuestion;

    const questions = await Model.find({ testId }).sort({ createdAt: 1 }).lean();
    res.json({ success: true, count: questions.length, questions, collectionName: test.collectionName || null });
  } catch (err) {
    console.error("Load free PCS questions error:", err);
    res.status(500).json({ success: false, message: "Failed to load free PCS questions" });
  }
});

app.get("/admin/test-questions/:testId", adminAuth, async (req, res) => {
  try {
    await Promise.all([connectQuestionDB(), connectFreePcsDB()]);
    const { testId } = req.params;

    const test = await Test.findById(testId).lean();
    if (!test) {
      return res.status(404).json({ success: false, message: "Test not found" });
    }

    const isFreePcs = !!test.collectionName;
    const Model = isFreePcs ? getFreePCSModel(test.collectionName) : Question;
    const docs = await Model.find({ testId }).sort({ createdAt: 1 }).lean();

    const questions = docs.map((q) => ({
      imageUrl: q.imageUrl || null,
      english: {
        question: q.english?.question || "",
        options: q.english?.options || {},
        english_explanation: q.english?.english_explanation || "",
      },
      hindi: {
        question: q.hindi?.question || "",
        options: q.hindi?.options || {},
        hindi_explanation: q.hindi?.hindi_explanation || "",
      },
      correct_answer: q.correct_answer,
    }));

    res.json({
      success: true,
      testId: test._id.toString(),
      title: test.title,
      testType: test.testType,
      phase: test.phase,
      isFreePcs,
      examType: isFreePcs ? (docs[0]?.examType || "") : undefined,
      year: isFreePcs ? (docs[0]?.year ?? null) : undefined,
      totalQuestions: questions.length,
      questions,
    });
  } catch (err) {
    console.error("Fetch test questions error:", err);
    res.status(500).json({ success: false, message: "Failed to load questions" });
  }
});

app.put("/admin/update-questions/:testId", adminAuth, async (req, res) => {
  try {
    await Promise.all([connectQuestionDB(), connectFreePcsDB()]);
    const { testId } = req.params;
    let { questions, examType, year } = req.body;

    if (!Array.isArray(questions) || questions.length === 0) {
      return res.status(400).json({ success: false, message: "questions must be a non-empty array" });
    }

    const test = await Test.findById(testId);
    if (!test) {
      return res.status(404).json({ success: false, message: "Test not found" });
    }

    const payloadErrors = questions.flatMap((q, idx) => validateQuestionPayload(q, idx));
    if (payloadErrors.length) {
      return res.status(400).json({
        success: false,
        message: "Invalid questions payload",
        errors: payloadErrors,
      });
    }

    const isFreePcs = !!test.collectionName;

    if (isFreePcs) {
      const Model = getFreePCSModel(test.collectionName);
      const existing = await Model.findOne({ testId }).lean();
      const finalExamType = (examType && String(examType).trim()) || existing?.examType;
      const finalYear = (year !== undefined && year !== null && !isNaN(Number(year)))
        ? Number(year)
        : existing?.year;

      if (!finalExamType || !finalYear) {
        return res.status(400).json({
          success: false,
          message: "examType and year are required (could not be inferred from existing data)",
        });
      }

      await Model.deleteMany({ testId });

      const qDocs = questions.map((q) => ({
        testId: test._id,
        title: test.title,
        examType: finalExamType,
        year: finalYear,
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

      await Model.insertMany(qDocs);

      test.totalQuestions = qDocs.length;
      await test.save();

      return res.json({
        success: true,
        message: `Free PCS paper "${test.title}" updated — ${qDocs.length} questions saved`,
        testId: test._id.toString(),
        totalQuestions: qDocs.length,
        examType: finalExamType,
        year: finalYear,
        availability: PERSISTENCE_NOTE,
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
        message: "Allowed question counts: 75 (daily), 100 (GS), 80 (CSAT) only",
      });
    }

    const questionPhase = (phase === "csat") ? "CSAT" : "GS";

    await Question.deleteMany({ testId });

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

    test.phase = phase;
    test.totalQuestions = numQuestions;
    await test.save();

    res.json({
      success: true,
      message: `Test "${test.title}" updated — ${numQuestions} questions saved`,
      testId: test._id.toString(),
      totalQuestions: numQuestions,
      phase,
      availability: PERSISTENCE_NOTE,
    });
  } catch (err) {
    console.error("Update questions error:", err);
    res.status(500).json({ success: false, message: err.message || "Update failed" });
  }
});

app.delete("/admin/delete-test/:testId", adminAuth, async (req, res) => {
  try {
    await Promise.all([connectUserDB(), connectQuestionDB(), connectFreePcsDB()]);

    const testId = req.params.testId;

    const test = await Test.findById(testId);
    if (!test) {
      return res.status(404).json({ success: false, message: "Test not found" });
    }

    const qResult = await Question.deleteMany({ testId });

    let pDeletedCount = 0;
    if (test.collectionName) {
      const Model = getFreePCSModel(test.collectionName);
      const pResult = await Model.deleteMany({ testId });
      pDeletedCount = pResult.deletedCount;
    } else {
      const pResult = await FreePCSQuestion.deleteMany({ testId });
      pDeletedCount = pResult.deletedCount;
    }

    const rResult  = await Result.deleteMany({ testId });
    const frResult = await FreeResult.deleteMany({ testId });

    await Test.findByIdAndDelete(testId);

    res.json({
      success: true,
      message: "Test, questions, and all user results deleted successfully",
      deleted: {
        questions:        qResult.deletedCount,
        freePcsQuestions: pDeletedCount,
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
