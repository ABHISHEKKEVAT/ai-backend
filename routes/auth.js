const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const { isDatabaseEnabled } = require("../config/env");
const auth = require("../middleware/auth");
const User = require("../models/User");

const signToken = (user) =>
  jwt.sign({ user: { id: user.id, role: user.role } }, process.env.JWT_SECRET, {
    expiresIn: "1d"
  });

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(value);
}

function escapeRegex(value) {
  return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function findUserByEmail(email) {
  return User.findOne({ email: new RegExp(`^${escapeRegex(email)}$`, "i") });
}

function clearVerificationFields(user) {
  user.isVerified = true;
  user.emailToken = undefined;
  user.emailVerifyCode = undefined;
  user.emailVerifyCodeExpire = undefined;
}

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

async function ensureAdminUser(req, res) {
  const me = await User.findById(req.user.id).select("role");
  if (!me || me.role !== "admin") {
    res.status(403).json({ msg: "Admin only" });
    return null;
  }

  return me;
}

// EMAIL VERIFICATION REMOVED
router.post("/resend-verify", async (req, res) => {
  return res.status(410).json({ msg: "Email verification is disabled." });
});

// SIGNUP
router.post("/signup", async (req, res) => {
  try {
    if (!ensureDatabaseReady(res)) return;

    const name = String(req.body.name || "").trim();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!name || !password) {
      return res.status(400).json({ msg: "Please fill all signup fields" });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ msg: "Please enter a valid email address." });
    }

    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ msg: "User already exists" });
    }

    const hash = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email,
      password: hash,
      isVerified: true,
      emailToken: undefined,
      emailVerifyCode: undefined,
      emailVerifyCodeExpire: undefined
    });

    await user.save();

    return res.json({ msg: "Signup successful." });
  } catch (err) {
    console.error(err);
    if (err && err.code === 11000) {
      return res.status(400).json({ msg: "User already exists" });
    }
    res.status(500).json({ msg: "Server error while creating account" });
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  try {
    if (!ensureDatabaseReady(res)) return;

    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({ msg: "Please enter email and password" });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ msg: "Please enter a valid email address." });
    }

    const user = await findUserByEmail(email);
    if (!user) return res.status(400).json({ msg: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" });

    if (!user.isVerified || user.emailToken || user.emailVerifyCode || user.emailVerifyCodeExpire) {
      clearVerificationFields(user);
      await user.save();
    }

    const token = signToken(user);
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: true,
        avatar: user.avatar,
        jobTitle: user.jobTitle,
        department: user.department
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
});

// EMAIL VERIFICATION REMOVED
router.get("/verify/:token", async (req, res) => {
  return res.status(410).send("Email verification is disabled.");
});

// EMAIL VERIFICATION REMOVED
router.post("/verify-code", async (req, res) => {
  return res.status(410).json({ msg: "Email verification is disabled." });
});

// FORGOT PASSWORD
router.post("/forgot", async (req, res) => {
  try {
    if (!ensureDatabaseReady(res)) return;

    const email = normalizeEmail(req.body.email);
    if (!email) {
      return res.status(400).json({ msg: "Email is required" });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ msg: "Please enter a valid email address." });
    }

    const user = await findUserByEmail(email);
    if (user) {
      user.resetToken = undefined;
      user.resetExpire = undefined;
      user.resetRequestedAt = new Date();
      await user.save();
    }

    return res.json({ msg: "Reset request submitted. Admin will reset your password." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
});

// ADMIN RESET PASSWORD (NO EMAIL LINK FLOW)
router.post("/admin/reset-password", auth, async (req, res) => {
  try {
    if (!ensureDatabaseReady(res)) return;

    const admin = await ensureAdminUser(req, res);
    if (!admin) return;

    const email = normalizeEmail(req.body.email);
    const userId = String(req.body.userId || "").trim();
    const password = String(req.body.password || "");

    if (!password || password.length < 6) {
      return res.status(400).json({ msg: "Password must be at least 6 characters" });
    }

    let user = null;
    if (email) {
      if (!isValidEmail(email)) {
        return res.status(400).json({ msg: "Please enter a valid email address." });
      }
      user = await findUserByEmail(email);
    } else if (userId) {
      if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ msg: "Invalid user ID" });
      }
      user = await User.findById(userId);
    } else {
      return res.status(400).json({ msg: "Email or user ID is required" });
    }

    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }

    user.password = await bcrypt.hash(password, 10);
    clearVerificationFields(user);
    user.resetToken = undefined;
    user.resetExpire = undefined;
    user.resetRequestedAt = undefined;
    await user.save();

    return res.json({ msg: `Password reset successfully for ${user.email}` });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: "Server error" });
  }
});

// RESET PASSWORD
router.post("/reset/:token", async (req, res) => {
  return res.status(410).json({
    msg: "Direct reset links are disabled. Submit a reset request and contact admin."
  });
});

module.exports = router;
