const express = require("express");
const cors = require("cors");
const path = require("path");
const dotenv = require("dotenv");
const connectDB = require("./config/db");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const CLIENT_URL = process.env.CLIENT_URL || "http://127.0.0.1:5500";
const CLIENT_URLS = (process.env.CLIENT_URLS || "")
  .split(",")
  .map((url) => url.trim())
  .filter(Boolean);

// Toggle DB usage easily while testing
const USE_DATABASE = process.env.USE_DATABASE === "true";

// Connect MongoDB only when enabled
if (USE_DATABASE) {
  connectDB();
} else {
  console.log("MongoDB disabled (USE_DATABASE=false)");
}

// Middleware
app.use(
  cors({
    origin: CLIENT_URLS.length > 0 ? CLIENT_URLS : [CLIENT_URL],
    credentials: true
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Health check
app.get("/", (req, res) => {
  res.json({
    ok: true,
    message: "Backend is running"
  });
});

// Routes
app.use("/api/auth", require("./routes/auth"));
app.use("/api/users", require("./routes/User"));
app.use("/api/chat", require("./routes/chat"));

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    ok: false,
    message: "Route not found"
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error("Server error:", err);

  if (err?.type === "entity.parse.failed") {
    return res.status(400).json({
      ok: false,
      message: "Invalid JSON body"
    });
  }

  res.status(500).json({
    ok: false,
    message: "Internal server error"
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
