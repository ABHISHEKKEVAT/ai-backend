const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
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

//verify
router.post("/resend-verify", async (req, res) => {
  try {
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
        avatar: user.avatar
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
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user)
      return res.json({ msg: "If that email exists, a reset link was sent." });

    const token = crypto.randomBytes(32).toString("hex");
    user.resetToken = token;
    user.resetExpire = Date.now() + 15 * 60 * 1000;
    await user.save();

    await transporter.sendMail({
      to: user.email,
      subject: "Password Reset",
      html: `Reset your password: <a href="${process.env.CLIENT_URL}/reset.html?token=${token}">Click here</a>`
    });

    res.json({ msg: "Reset link sent if email exists." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
});

// RESET PASSWORD
router.post("/reset/:token", async (req, res) => {
  try {
    const user = await User.findOne({
      resetToken: req.params.token,
      resetExpire: { $gt: Date.now() }
    });
    if (!user) return res.status(400).send("Invalid or expired token");

    const hash = await bcrypt.hash(req.body.password, 10);
    user.password = hash;
    user.resetToken = undefined;
    user.resetExpire = undefined;
    await user.save();

    res.send("Password updated successfully.");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

module.exports = router;
