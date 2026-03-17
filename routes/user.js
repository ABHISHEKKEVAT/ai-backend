const express = require("express");
const router = express.Router();
const multer = require("multer");
const path = require("path");
const auth = require("../middleware/auth");
const User = require("../models/User");

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "-" + Math.round(Math.random() * 1e9) + path.extname(file.originalname))
});
const upload = multer({ storage });

// GET ME
router.get("/me", auth, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  res.json(user);
});

// UPDATE ME
router.post("/me", auth, upload.single("avatar"), async (req, res) => {
  const update = { name: req.body.name };
  if (req.file) update.avatar = "/uploads/" + req.file.filename;

  const user = await User.findByIdAndUpdate(req.user.id, update, { new: true }).select("-password");
  res.json(user);
});

// ADMIN: GET ALL USERS
router.get("/all", auth, async (req, res) => {
  const me = await User.findById(req.user.id);
  if (!me || me.role !== "admin")
    return res.status(403).json({ msg: "Admin only" });

  const users = await User.find().select("-password");
  res.json(users);
});

module.exports = router;
