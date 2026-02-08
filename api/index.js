require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");

const app = express();

// ================= SECURITY =================
app.use(express.json({ limit: "10kb" }));
app.use(cors());
app.use(helmet());
app.use(compression());

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 500
  })
);

// ================= DATABASE (SERVERLESS SAFE) =================
let cached = global.mongoose;
if (!cached) cached = global.mongoose = { conn: null, promise: null };

async function connectDB() {
  if (cached.conn) return cached.conn;

  if (!cached.promise) {
    cached.promise = mongoose
      .connect(process.env.MONGO_URI)
      .then((mongoose) => {
        console.log("Admin DB Connected");
        return mongoose;
      });
  }
  cached.conn = await cached.promise;
  return cached.conn;
}

// ================= SCHEMAS =================
const testSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    date: { type: String, required: true }, // YYYY-MM-DD
    startTime: Date, // optional if you want time-based activation
    endTime: Date,   // optional
    isActive: { type: Boolean, default: false },
    totalQuestions: { type: Number, default: 0 }
  },
  { timestamps: true }
);

const questionSchema = new mongoose.Schema(
  {
    testId: { type: mongoose.Schema.Types.ObjectId, ref: "Test", required: true },
    questionNumber: { type: Number, required: true },
    questionStatement: { type: String, required: true },
    options: {
      option1: String,
      option2: String,
      option3: String,
      option4: String
    },
    correctOption: { type: String, enum: ["option1", "option2", "option3", "option4"], required: true }
  },
  { timestamps: true }
);

// Models (avoid recompilation in serverless)
const Test = mongoose.models.Test || mongoose.model("Test", testSchema);
const Question = mongoose.models.Question || mongoose.model("Question", questionSchema);

// ================= ADMIN AUTH =================
const adminAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "No token provided" });

  const token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : authHeader;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// ================= ROUTES =================

// Health check for Vercel
app.get("/", (req, res) => {
  res.json({ status: "Admin Backend Running" });
});

// CREATE TEST
app.post("/admin/create-test", adminAuth, async (req, res) => {
  await connectDB();

  const { title, date, startTime, endTime } = req.body;

  const exists = await Test.findOne({ date });
  if (exists) return res.status(400).json({ message: "Test already exists for this date" });

  const test = await Test.create({ title, date, startTime, endTime });
  res.json(test);
});

// ADD QUESTION
app.post("/admin/add-question/:testId", adminAuth, async (req, res) => {
  await connectDB();

  const { questionNumber, questionStatement, options, correctOption } = req.body;

  const question = await Question.create({
    testId: req.params.testId,
    questionNumber,
    questionStatement,
    options,
    correctOption
  });

  // Increment totalQuestions in Test
  await Test.findByIdAndUpdate(req.params.testId, { $inc: { totalQuestions: 1 } });

  res.json(question);
});

// DELETE TEST (and its questions)
app.delete("/admin/delete-test/:testId", adminAuth, async (req, res) => {
  await connectDB();

  await Question.deleteMany({ testId: req.params.testId });
  await Test.findByIdAndDelete(req.params.testId);

  res.json({ message: "Test deleted successfully" });
});

// DELETE SINGLE QUESTION
app.delete("/admin/delete-question/:questionId", adminAuth, async (req, res) => {
  await connectDB();

  await Question.findByIdAndDelete(req.params.questionId);
  res.json({ message: "Question deleted successfully" });
});

// GET ALL TESTS
app.get("/admin/tests", adminAuth, async (req, res) => {
  await connectDB();

  const tests = await Test.find().sort({ date: -1 });
  res.json(tests);
});

// GET QUESTIONS OF A TEST
app.get("/admin/questions/:testId", adminAuth, async (req, res) => {
  await connectDB();

  const questions = await Question.find({ testId: req.params.testId }).sort({ questionNumber: 1 });
  res.json(questions);
});

module.exports = app;
