const express = require("express");
const router = express.Router();
const multer = require("multer");
const path = require("path");
const mongoose = require("mongoose");
const { isDatabaseEnabled } = require("../config/env");
const auth = require("../middleware/auth");
const User = require("../models/User");

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "-" + Math.round(Math.random() * 1e9) + path.extname(file.originalname))
});
const upload = multer({ storage });

function ensureDatabaseReady(res) {
  if (!isDatabaseEnabled()) {
    res.status(503).json({ msg: "Database is disabled. Set USE_DATABASE=true or configure MONGO_URI." });
    return false;
  }

  if (mongoose.connection.readyState !== 1) {
    res.status(503).json({ msg: "Database is not connected. Try again shortly." });
    return false;
  }

  return true;
}

// GET ME
router.get("/me", auth, async (req, res) => {
  try {
    if (!ensureDatabaseReady(res)) return;

    const user = await User.findById(req.user.id).select("-password");
    if (!user) return res.status(404).json({ msg: "User not found" });

    return res.json(user);
  } catch (err) {
    console.error("GET /users/me error:", err);
    return res.status(500).json({ msg: "Server error" });
  }
});

// UPDATE ME
router.post("/me", auth, upload.single("avatar"), async (req, res) => {
  try {
    if (!ensureDatabaseReady(res)) return;

    const update = { name: req.body.name };
    if (req.file) update.avatar = "/uploads/" + req.file.filename;

    const user = await User.findByIdAndUpdate(req.user.id, update, { new: true }).select("-password");
    if (!user) return res.status(404).json({ msg: "User not found" });

    return res.json(user);
  } catch (err) {
    console.error("POST /users/me error:", err);
    return res.status(500).json({ msg: "Server error" });
  }
});

// ADMIN: GET ALL USERS
router.get("/all", auth, async (req, res) => {
  try {
    if (!ensureDatabaseReady(res)) return;

    const me = await User.findById(req.user.id);
    if (!me || me.role !== "admin") {
      return res.status(403).json({ msg: "Admin only" });
    }

    const users = await User.find().select("-password");
    return res.json(users);
  } catch (err) {
    console.error("GET /users/all error:", err);
    return res.status(500).json({ msg: "Server error" });
  }
});

module.exports = router;
