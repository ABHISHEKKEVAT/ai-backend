const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const mongoose = require("mongoose");
const { isDatabaseEnabled } = require("../config/env");
const auth = require("../middleware/auth");
const User = require("../models/User");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const signToken = (user) =>
  jwt.sign({ user: { id: user.id, role: user.role } }, process.env.JWT_SECRET, {
    expiresIn: "1d"
  });

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

//verify
router.post("/resend-verify", async (req, res) => {
  try {
    if (!ensureDatabaseReady(res)) return;

    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: "User not found" });
    if (user.isVerified) return res.json({ msg: "Already verified" });

    const emailToken = crypto.randomBytes(32).toString("hex");
    user.emailToken = emailToken;
    await user.save();

    await transporter.sendMail({
      to: user.email,
      subject: "Verify your email",
      html: `Click <a href="${process.env.CLIENT_URL}/verify.html?token=${emailToken}">here</a> to verify your email.`
    });

    res.json({ msg: "Verification email resent" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
});


// SIGNUP
router.post("/signup", async (req, res) => {
  try {
    if (!ensureDatabaseReady(res)) return;

    const { name, email, password } = req.body;
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: "User already exists" });

    const hash = await bcrypt.hash(password, 10);
    const emailToken = crypto.randomBytes(32).toString("hex");

    user = new User({ name, email, password: hash, emailToken });
    await user.save();

    const link = `${process.env.CLIENT_URL}/?verify=${emailToken}`;
    await transporter.sendMail({
      to: email,
      subject: "Verify your email",
      html: `Click <a href="${process.env.CLIENT_URL}/verify.html?token=${emailToken}">here</a> to verify your email.`
    });

    res.json({ msg: "Signup successful. Check your email to verify." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  try {
    if (!ensureDatabaseReady(res)) return;

    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" });

    const token = signToken(user);
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified,
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

// VERIFY EMAIL
router.get("/verify/:token", async (req, res) => {
  try {
    if (!ensureDatabaseReady(res)) return res.status(503).send("Database unavailable");

    const user = await User.findOne({ emailToken: req.params.token });
    if (!user) return res.status(400).send("Invalid or expired token");

    user.isVerified = true;
    user.emailToken = undefined;
    await user.save();

    res.send("Email verified successfully. You can close this tab.");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// FORGOT PASSWORD
router.post("/forgot", async (req, res) => {
  try {
    if (!ensureDatabaseReady(res)) return;

    const email = String(req.body.email || "").trim();
    if (!email) {
      return res.status(400).json({ msg: "Email is required" });
    }

    const user = await User.findOne({ email });
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

    const email = String(req.body.email || "").trim();
    const userId = String(req.body.userId || "").trim();
    const password = String(req.body.password || "");

    if (!password || password.length < 6) {
      return res.status(400).json({ msg: "Password must be at least 6 characters" });
    }

    const query = {};
    if (email) {
      query.email = email;
    } else if (userId) {
      if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ msg: "Invalid user ID" });
      }
      query._id = userId;
    } else {
      return res.status(400).json({ msg: "Email or user ID is required" });
    }

    const user = await User.findOne(query);
    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }

    user.password = await bcrypt.hash(password, 10);
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
