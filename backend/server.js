require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const admin = require("firebase-admin");
const fs = require("fs");
const path = require("path");

const errorHandler = require("./middleware/errorHandler");
require("./config/clients"); // redis/twilio safe

const app = express();

/* ================= MIDDLEWARE ================= */
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

/* ================= FIREBASE ADMIN ================= */
const serviceAccountPath = "/etc/secrets/firebase-service-account.json";

if (!admin.apps.length) {
  if (!fs.existsSync(serviceAccountPath)) {
    console.error("❌ Firebase service account file not found at:", serviceAccountPath);
    process.exit(1);
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccountPath),
  });

  console.log("✅ Firebase Admin initialized");
}

/* ================= MONGODB ================= */
if (!process.env.MONGO_URI) {
  console.error("❌ MONGO_URI missing");
  process.exit(1);
}

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB error:", err.message);
    process.exit(1);
  });

/* ================= HEALTH ================= */
app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

/* ================= ROUTES ================= */
app.use("/api/auth", require("./routes/auth"));
app.use("/api", require("./routes/logistics"));

/* ================= ERRORS ================= */
app.use(errorHandler);

/* ================= START ================= */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
