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
app.use(express.json({ limit: "10kb" }));
app.use(cors());
app.use(helmet());
app.use(compression());

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300
  })
);
let isConnected = false;

const connectDB = async () => {
  if (isConnected) return;

  const db = await mongoose.connect(process.env.MONGO_URI);
  isConnected = db.connections[0].readyState === 1;
  console.log("Admin DB Connected");
};

connectDB();
const testSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    date: { type: String, required: true },
    startTime: Date,
    endTime: Date,
    isActive: { type: Boolean, default: false },
    totalQuestions: { type: Number, default: 0 }
  },
  { timestamps: true }
);

const questionSchema = new mongoose.Schema(
  {
    testId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Test",
      required: true
    },
    questionNumber: { type: Number, required: true },
    questionStatement: { type: String, required: true },
    options: {
      option1: String,
      option2: String,
      option3: String,
      option4: String
    },
    correctOption: {
      type: String,
      enum: ["option1", "option2", "option3", "option4"],
      required: true
    }
  },
  { timestamps: true }
);

const adminSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String
});

const Test = mongoose.model("Test", testSchema);
const Question = mongoose.model("Question", questionSchema);
const Admin = mongoose.model("Admin", adminSchema);

const adminAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader)
    return res.status(401).json({ message: "No token provided" });

  const token = authHeader.startsWith("Bearer ")
    ? authHeader.split(" ")[1]
    : authHeader;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};
const createDefaultAdmin = async () => {
  const exists = await Admin.findOne({ email: "admin@bpsc.com" });
  if (!exists) {
    const hashed = await bcrypt.hash("admin123", 12);
    await Admin.create({
      email: "admin@bpsc.com",
      password: hashed
    });
    console.log("Default Admin Created");
  }
};

createDefaultAdmin();

// HEALTH CHECK (important for Vercel)
app.get("/", (req, res) => {
  res.json({ message: "Admin Backend Running" });
});
app.post("/admin/login", async (req, res) => {
  const { email, password } = req.body;

  const admin = await Admin.findOne({ email });
  if (!admin)
    return res.status(400).json({ message: "Admin not found" });

  const valid = await bcrypt.compare(password, admin.password);
  if (!valid)
    return res.status(400).json({ message: "Wrong password" });

  const token = jwt.sign(
    { id: admin._id },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );

  res.json({ token });
});
app.post("/admin/create-test", adminAuth, async (req, res) => {
  const { title, startTime, endTime } = req.body;

  const today = new Date().toISOString().split("T")[0];

  const test = await Test.create({
    title,
    date: today,
    startTime,
    endTime
  });

  res.json(test);
});

// ADD QUESTION
app.post("/admin/add-question/:testId", adminAuth, async (req, res) => {
  const { questionNumber, questionStatement, options, correctOption } =
    req.body;

  const question = await Question.create({
    testId: req.params.testId,
    questionNumber,
    questionStatement,
    options,
    correctOption
  });

  await Test.findByIdAndUpdate(req.params.testId, {
    $inc: { totalQuestions: 1 }
  });

  res.json(question);
});

// DELETE QUESTION
app.delete("/admin/delete-question/:id", adminAuth, async (req, res) => {
  await Question.findByIdAndDelete(req.params.id);
  res.json({ message: "Question Deleted Successfully" });
});

// DASHBOARD
app.get("/admin/dashboard", adminAuth, async (req, res) => {
  const totalTests = await Test.countDocuments();
  const totalQuestions = await Question.countDocuments();

  res.json({
    totalTests,
    totalQuestions
  });
});
module.exports = app;
