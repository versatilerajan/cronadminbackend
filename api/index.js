require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");

const app = express();

app.use(helmet());
app.use(compression());
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 400,
  })
);
app.use(express.json({ limit: "100kb" }));

app.use(
  cors({
    origin: true,
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
    optionsSuccessStatus: 204,
  })
);

app.options("*", cors());

// Just a health check
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Backend is alive (DB disabled for testing)",
    env: {
      hasMongoUri: !!process.env.MONGO_URI,
      hasJwtSecret: !!process.env.JWT_SECRET,
      nodeEnv: process.env.NODE_ENV,
    },
  });
});

app.get("/test", (req, res) => {
  res.json({ success: true, message: "Test route working" });
});

// Keep login stub (no DB)
app.post("/admin/login", (req, res) => {
  const { email, password } = req.body;
  if (email === "admin@bpsc.com" && password === "admin123") {
    res.json({ success: true, token: "fake-jwt-for-testing-only" });
  } else {
    res.status(401).json({ success: false, message: "Invalid credentials" });
  }
});

module.exports = app;
