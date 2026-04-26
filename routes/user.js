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

function normalizeText(value) {
  return String(value || "").trim();
}

function truncate(value, max) {
  return normalizeText(value).slice(0, max);
}

function normalizeJoinDate(value) {
  const raw = normalizeText(value);
  if (!raw) return null;
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return undefined;
  return date;
}

function normalizeHttpUrl(value) {
  const raw = normalizeText(value);
  if (!raw) return "";

  try {
    const parsed = new URL(raw);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      return parsed.toString().slice(0, 200);
    }
    return undefined;
  } catch {
    return undefined;
  }
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

    const currentUser = await User.findById(req.user.id).select("name");
    if (!currentUser) return res.status(404).json({ msg: "User not found" });

    const update = {};

    if (typeof req.body.name !== "undefined") update.name = truncate(req.body.name, 80);
    if (typeof req.body.phone !== "undefined") update.phone = truncate(req.body.phone, 32);
    if (typeof req.body.jobTitle !== "undefined") update.jobTitle = truncate(req.body.jobTitle, 80);
    if (typeof req.body.department !== "undefined") update.department = truncate(req.body.department, 80);
    if (typeof req.body.location !== "undefined") update.location = truncate(req.body.location, 120);
    if (typeof req.body.employeeId !== "undefined") update.employeeId = truncate(req.body.employeeId, 40);
    if (typeof req.body.managerName !== "undefined") update.managerName = truncate(req.body.managerName, 80);
    if (typeof req.body.bio !== "undefined") update.bio = truncate(req.body.bio, 800);
    if (typeof req.body.skills !== "undefined") update.skills = truncate(req.body.skills, 400);
    if (typeof req.body.linkedinUrl !== "undefined") {
      const normalizedLinkedinUrl = normalizeHttpUrl(req.body.linkedinUrl);
      if (typeof normalizedLinkedinUrl === "undefined") {
        return res.status(400).json({ msg: "Invalid LinkedIn URL" });
      }
      update.linkedinUrl = normalizedLinkedinUrl;
    }

    if (typeof req.body.joinDate !== "undefined") {
      const normalized = normalizeJoinDate(req.body.joinDate);
      if (typeof normalized === "undefined") {
        return res.status(400).json({ msg: "Invalid join date" });
      }
      update.joinDate = normalized;
    }

    if (req.file) update.avatar = "/uploads/" + req.file.filename;

    if (!update.name) update.name = currentUser.name;

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
