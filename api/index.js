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

// ─── Middleware ────────────────────────────────────────────────
app.use(helmet());
app.use(compression());

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 400,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use(express.json({ limit: "100kb" }));

// Very permissive CORS for development → tighten later in production
app.use(
  cors({
    origin: [
      "https://cronadminbackend.vercel.app",
      "http://localhost:3000",
      "http://127.0.0.1:3000",
      "http://localhost:5173",     // common vite port
      "*",                         // ← temporary broad access (remove or restrict later)
    ],
    methods: ["GET", "POST", "DELETE", "OPTIONS", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
    optionsSuccessStatus: 204,
  })
);

// Handle preflight OPTIONS requests explicitly
app.options("*", cors());

// ─── MongoDB Connection (cached for serverless) ────────────────
const mongooseCache = global.mongoose || { conn: null, promise: null };
global.mongoose = mongooseCache;

async function connectDB() {
  if (mongooseCache.conn) return mongooseCache.conn;

  if (!mongooseCache.promise) {
    const opts = {
      bufferCommands: false,
      serverSelectionTimeoutMS: 5000,
      maxPoolSize: 10,
    };

    mongooseCache.promise = mongoose
      .connect(process.env.MONGO_URI, opts)
      .then((mongoose) => {
        console.log("MongoDB connected successfully");
        return mongoose;
      })
      .catch((err) => {
        console.error("MongoDB connection failed:", err.message);
        mongooseCache.promise = null;
        throw err;
      });
  }

  mongooseCache.conn = await mongooseCache.promise;
  return mongooseCache.conn;
}

// ─── Schemas ───────────────────────────────────────────────────
const testSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true, maxlength: 200 },
    date: { type: String, required: true, match: /^\d{4}-\d{2}-\d{2}$/ },
    startTime: { type: Date },
    endTime: { type: Date },
    isActive: { type: Boolean, default: false },
    totalQuestions: { type: Number, default: 0 },
  },
  { timestamps: true }
);

const questionSchema = new mongoose.Schema(
  {
    testId: { type: mongoose.Schema.Types.ObjectId, ref: "Test", required: true },
    questionNumber: { type: Number, required: true, min: 1, max: 100 },
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
  password: { type: String, required: true, minlength: 8 },
});

const Test = mongoose.models.Test || mongoose.model("Test", testSchema);
const Question = mongoose.models.Question || mongoose.model("Question", questionSchema);
const Admin = mongoose.models.Admin || mongoose.model("Admin", adminSchema);

// ─── Auth Middleware ───────────────────────────────────────────
function adminAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, message: "Authorization header missing or invalid" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.adminId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: "Invalid or expired token" });
  }
}

// ─── Create default admin if missing ───────────────────────────
async function ensureDefaultAdmin() {
  try {
    await connectDB();
    const exists = await Admin.findOne({ email: "admin@bpsc.com" });
    if (!exists) {
      const hashed = await bcrypt.hash("admin123", 12);
      await Admin.create({ email: "admin@bpsc.com", password: hashed });
      console.log("Default admin account created");
    }
  } catch (err) {
    console.error("Could not create default admin:", err.message);
  }
}

ensureDefaultAdmin().catch(console.error);

// ─── Routes ────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({ success: true, message: "Admin backend is running" });
});

app.post("/admin/login", async (req, res) => {
  try {
    await connectDB();

    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: "Email and password are required" });
    }

    const admin = await Admin.findOne({ email: email.toLowerCase().trim() });
    if (!admin) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const passwordMatch = await bcrypt.compare(password, admin.password);
    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: "24h" });

    res.json({ success: true, token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, message: "Server error during login" });
  }
});

// Bulk create test + 50 questions
app.post("/admin/create-test-with-questions", adminAuth, async (req, res) => {
  try {
    await connectDB();

    const { title, date, startTime, endTime, questions } = req.body;

    if (!title || !date || !Array.isArray(questions)) {
      return res.status(400).json({ success: false, message: "title, date and questions array are required" });
    }

    if (questions.length !== 50) {
      return res.status(400).json({ success: false, message: "Exactly 50 questions are required" });
    }

    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ success: false, message: "Date must be in YYYY-MM-DD format" });
    }

    const existingTest = await Test.findOne({ date });
    if (existingTest) {
      return res.status(409).json({ success: false, message: "A test already exists for this date" });
    }

    const test = await Test.create({
      title: title.trim(),
      date,
      startTime: startTime ? new Date(startTime) : undefined,
      endTime: endTime ? new Date(endTime) : undefined,
      totalQuestions: 50,
    });

    const questionDocs = questions.map((q, idx) => ({
      testId: test._id,
      questionNumber: q.questionNumber || idx + 1,
      questionStatement: (q.questionStatement || "").trim(),
      options: {
        option1: (q.options?.option1 || "").trim(),
        option2: (q.options?.option2 || "").trim(),
        option3: (q.options?.option3 || "").trim(),
        option4: (q.options?.option4 || "").trim(),
      },
      correctOption: q.correctOption,
    }));

    await Question.insertMany(questionDocs);

    res.json({
      success: true,
      message: "Test and questions created",
      test: { _id: test._id, title: test.title, date: test.date },
    });
  } catch (err) {
    console.error("Create test error:", err);
    res.status(500).json({ success: false, message: err.message || "Failed to create test" });
  }
});

app.get("/admin/tests", adminAuth, async (req, res) => {
  try {
    await connectDB();
    const tests = await Test.find().sort({ date: -1 }).lean();
    res.json({ success: true, tests });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to fetch tests" });
  }
});

app.delete("/admin/delete-test/:testId", adminAuth, async (req, res) => {
  try {
    await connectDB();

    const test = await Test.findById(req.params.testId);
    if (!test) {
      return res.status(404).json({ success: false, message: "Test not found" });
    }

    await Question.deleteMany({ testId: req.params.testId });
    await Test.findByIdAndDelete(req.params.testId);

    res.json({ success: true, message: "Test and all related questions deleted" });
  } catch (err) {
    console.error("Delete test error:", err);
    res.status(500).json({ success: false, message: "Server error while deleting test" });
  }
});

// Optional: keep these if you still want single-question add/delete
app.post("/admin/add-question/:testId", adminAuth, async (req, res) => {
  try {
    await connectDB();
    const { questionNumber, questionStatement, options, correctOption } = req.body;

    const question = await Question.create({
      testId: req.params.testId,
      questionNumber,
      questionStatement,
      options,
      correctOption,
    });

    await Test.findByIdAndUpdate(req.params.testId, { $inc: { totalQuestions: 1 } });

    res.json({ success: true, question });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to add question" });
  }
});

app.delete("/admin/delete-question/:questionId", adminAuth, async (req, res) => {
  try {
    await connectDB();
    const question = await Question.findById(req.params.questionId);
    if (!question) return res.status(404).json({ success: false, message: "Question not found" });

    await question.deleteOne();
    await Test.findByIdAndUpdate(question.testId, { $inc: { totalQuestions: -1 } });

    res.json({ success: true, message: "Question deleted" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to delete question" });
  }
});
module.exports = app;
