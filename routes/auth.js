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

const mailUser = String(process.env.EMAIL_USER || "").trim();
const mailPass = String(process.env.EMAIL_PASS || "").trim();
const smtpHost = String(process.env.SMTP_HOST || "").trim();
const smtpPort = Number(process.env.SMTP_PORT || 587);
const smtpSecure = String(process.env.SMTP_SECURE || "false").trim().toLowerCase() === "true";
const mailFrom = String(process.env.EMAIL_FROM || mailUser || "no-reply@example.com").trim();
const verifyCodeTTLMinutes = Number(process.env.EMAIL_VERIFY_CODE_TTL_MINUTES || 15);
const defaultClientUrl = String(process.env.CLIENT_URL || "http://127.0.0.1:5500").trim();

const transporter = smtpHost
  ? nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpSecure,
      auth: mailUser && mailPass ? { user: mailUser, pass: mailPass } : undefined
    })
  : nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: mailUser,
        pass: mailPass
      }
    });

const signToken = (user) =>
  jwt.sign({ user: { id: user.id, role: user.role } }, process.env.JWT_SECRET, {
    expiresIn: "1d"
  });

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidEmail(value) {
  // Accepts common providers (gmail/yahoo/etc.) and any valid domain format.
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(value);
}

function isValidVerificationCode(value) {
  return /^\d{6}$/.test(String(value || "").trim());
}

function escapeRegex(value) {
  return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function findUserByEmail(email) {
  return User.findOne({ email: new RegExp(`^${escapeRegex(email)}$`, "i") });
}

function isMailConfigured() {
  return Boolean(mailUser && mailPass);
}

function buildVerifyLink(emailToken) {
  return `${defaultClientUrl}/verify.html?token=${encodeURIComponent(emailToken)}`;
}

function setEmailVerificationSecrets(user) {
  user.emailToken = crypto.randomBytes(32).toString("hex");
  user.emailVerifyCode = String(Math.floor(100000 + Math.random() * 900000));
  user.emailVerifyCodeExpire = new Date(Date.now() + verifyCodeTTLMinutes * 60 * 1000);
}

async function sendVerificationEmail(user) {
  if (!isMailConfigured()) {
    throw new Error("MAIL_NOT_CONFIGURED");
  }

  const verifyLink = buildVerifyLink(user.emailToken);
  const codeExpiryText = `${verifyCodeTTLMinutes} minute${verifyCodeTTLMinutes === 1 ? "" : "s"}`;

  await transporter.sendMail({
    from: mailFrom,
    to: user.email,
    subject: "Verify your email address",
    html: `
      <p>Hello ${user.name || "there"},</p>
      <p>Your verification code is <strong>${user.emailVerifyCode}</strong>.</p>
      <p>This code expires in ${codeExpiryText}.</p>
      <p>Or verify directly by clicking <a href="${verifyLink}">this link</a>.</p>
      <p>If you did not create this account, you can ignore this email.</p>
    `
  });
}

async function trySendVerificationEmail(user) {
  try {
    await sendVerificationEmail(user);
    return true;
  } catch (err) {
    if (String(err.message || "") === "MAIL_NOT_CONFIGURED") {
      return false;
    }
    console.error("Verification email send failed:", err);
    return false;
  }
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

//verify
router.post("/resend-verify", async (req, res) => {
  try {
    if (!ensureDatabaseReady(res)) return;

    if (!isMailConfigured()) {
      return res.status(500).json({
        msg: "Email service is not configured. Set EMAIL_USER and EMAIL_PASS (app password)."
      });
    }

    const email = normalizeEmail(req.body.email);
    if (!isValidEmail(email)) {
      return res.status(400).json({ msg: "Please enter a valid email address." });
    }

    const user = await findUserByEmail(email);
    if (!user) return res.status(400).json({ msg: "User not found" });
    if (user.isVerified) return res.json({ msg: "Already verified" });

    setEmailVerificationSecrets(user);
    await user.save();

    await sendVerificationEmail(user);

    res.json({ msg: "Verification email resent" });
  } catch (err) {
    console.error(err);
    if (String(err.message || "") === "MAIL_NOT_CONFIGURED") {
      return res.status(500).json({
        msg: "Email service is not configured. Set EMAIL_USER and EMAIL_PASS (app password)."
      });
    }
    res.status(500).json({ msg: "Server error while sending verification email" });
  }
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

    const hash = await bcrypt.hash(password, 10);
    let user = await findUserByEmail(email);

    if (user) {
      if (user.isVerified) {
        return res.status(400).json({ msg: "User already exists" });
      }

      // Allow retry for unverified users: refresh password + verification secrets.
      user.name = name;
      user.password = hash;
      setEmailVerificationSecrets(user);
      await user.save();
      const verificationEmailSent = await trySendVerificationEmail(user);

      return res.json({
        msg: verificationEmailSent
          ? "Account already created but not verified. Verification code resent."
          : "Account already created but not verified. Verification email could not be sent right now."
      });
    }

    user = new User({ name, email, password: hash });
    setEmailVerificationSecrets(user);
    await user.save();
    const verificationEmailSent = await trySendVerificationEmail(user);

    return res.json({
      msg: verificationEmailSent
        ? "Signup successful. Check your email for verification code."
        : "Signup successful, but verification email could not be sent right now."
    });
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
    user.emailVerifyCode = undefined;
    user.emailVerifyCodeExpire = undefined;
    await user.save();

    res.send("Email verified successfully. You can go back and log in.");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// VERIFY EMAIL WITH CODE
router.post("/verify-code", async (req, res) => {
  try {
    if (!ensureDatabaseReady(res)) return;

    const email = normalizeEmail(req.body.email);
    const code = String(req.body.code || "").trim();

    if (!isValidEmail(email)) {
      return res.status(400).json({ msg: "Please enter a valid email address." });
    }
    if (!isValidVerificationCode(code)) {
      return res.status(400).json({ msg: "Please enter a valid 6-digit verification code." });
    }

    const user = await findUserByEmail(email);
    if (!user) return res.status(404).json({ msg: "User not found" });
    if (user.isVerified) return res.json({ msg: "Email already verified." });

    const now = Date.now();
    const expiresAt = user.emailVerifyCodeExpire ? new Date(user.emailVerifyCodeExpire).getTime() : 0;
    if (!user.emailVerifyCode || !expiresAt || now > expiresAt) {
      return res.status(400).json({ msg: "Verification code expired. Please request a new one." });
    }
    if (user.emailVerifyCode !== code) {
      return res.status(400).json({ msg: "Invalid verification code." });
    }

    user.isVerified = true;
    user.emailToken = undefined;
    user.emailVerifyCode = undefined;
    user.emailVerifyCodeExpire = undefined;
    await user.save();

    return res.json({ msg: "Email verified successfully." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: "Server error" });
  }
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
