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

const PASSWORD_POLICY_TEXT =
  "Password must be 8-64 characters and include uppercase, lowercase, number, and special character.";

function validatePasswordPolicy(value) {
  const password = String(value || "");

  if (password.length < 8 || password.length > 64) {
    return { ok: false, msg: PASSWORD_POLICY_TEXT };
  }
  if (/\s/.test(password)) {
    return { ok: false, msg: "Password cannot contain spaces." };
  }
  if (!/[a-z]/.test(password)) {
    return { ok: false, msg: "Password must include at least one lowercase letter." };
  }
  if (!/[A-Z]/.test(password)) {
    return { ok: false, msg: "Password must include at least one uppercase letter." };
  }
  if (!/[0-9]/.test(password)) {
    return { ok: false, msg: "Password must include at least one number." };
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return { ok: false, msg: "Password must include at least one special character." };
  }

  return { ok: true, msg: "" };
}

function escapeRegex(value) {
  return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function findUserByEmail(email) {
  return User.findOne({ email: new RegExp(`^${escapeRegex(email)}$`, "i") });
}

function normalizeRole(value) {
  return String(value || "").trim().toLowerCase() === "admin" ? "admin" : "user";
}

function normalizeCode(value) {
  return String(value || "").trim();
}

function getEmployeeIdPrefix(role) {
  return role === "admin" ? "Adm-" : "Emp-";
}

function formatEmployeeId(prefix, number) {
  return `${prefix}${String(number).padStart(3, "0")}`;
}

async function getNextEmployeeId(role) {
  const prefix = getEmployeeIdPrefix(role);
  const regex = new RegExp(`^${escapeRegex(prefix)}\\d+$`, "i");
  const users = await User.find({ role, employeeId: regex }).select("employeeId").lean();

  let maxIdNumber = 0;
  for (const user of users) {
    const match = String(user.employeeId || "").match(/\d+$/);
    if (!match) continue;
    const parsed = Number.parseInt(match[0], 10);
    if (Number.isInteger(parsed) && parsed > maxIdNumber) {
      maxIdNumber = parsed;
    }
  }

  return formatEmployeeId(prefix, maxIdNumber + 1);
}

function isEmployeeIdDuplicateKeyError(err) {
  if (!err || err.code !== 11000) return false;
  if (err.keyPattern && err.keyPattern.employeeId) return true;
  return String(err.message || "").toLowerCase().includes("employeeid");
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
    const role = normalizeRole(req.body.role);
    const adminCode = normalizeCode(req.body.adminCode);

    if (!name || !password) {
      return res.status(400).json({ msg: "Please fill all signup fields" });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ msg: "Please enter a valid email address." });
    }
    const passwordValidation = validatePasswordPolicy(password);
    if (!passwordValidation.ok) {
      return res.status(400).json({ msg: passwordValidation.msg });
    }
    if (role === "admin") {
      const expectedAdminCode = normalizeCode(process.env.ADMIN_SIGNUP_CODE);
      if (!expectedAdminCode) {
        return res.status(503).json({ msg: "Admin signup is not configured. Please contact system admin." });
      }
      if (!adminCode) {
        return res.status(400).json({ msg: "Admin verification code is required." });
      }
      if (adminCode !== expectedAdminCode) {
        return res.status(403).json({ msg: "Invalid admin verification code." });
      }
    }

    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ msg: "User already exists" });
    }

    const hash = await bcrypt.hash(password, 10);
    let user = null;

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const employeeId = await getNextEmployeeId(role);

      user = new User({
        name,
        email,
        password: hash,
        role,
        employeeId,
        isVerified: true,
        emailToken: undefined,
        emailVerifyCode: undefined,
        emailVerifyCodeExpire: undefined
      });

      try {
        await user.save();
        break;
      } catch (saveError) {
        if (isEmployeeIdDuplicateKeyError(saveError)) {
          user = null;
          continue;
        }
        throw saveError;
      }
    }

    if (!user) {
      return res.status(500).json({ msg: "Failed to generate employee ID. Please try again." });
    }

    return res.json({ msg: "Signup successful.", employeeId: user.employeeId, role: user.role });
  } catch (err) {
    console.error(err);
    if (err && err.code === 11000) {
      const duplicateFields = Object.keys(err.keyPattern || {});
      if (duplicateFields.includes("email")) {
        return res.status(400).json({ msg: "User already exists" });
      }
      if (duplicateFields.includes("employeeId")) {
        return res.status(409).json({ msg: "Employee ID conflict. Please try signup again." });
      }
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
        employeeId: user.employeeId,
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

    const passwordValidation = validatePasswordPolicy(password);
    if (!passwordValidation.ok) {
      return res.status(400).json({ msg: passwordValidation.msg });
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
