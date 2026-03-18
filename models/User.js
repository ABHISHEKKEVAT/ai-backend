const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: "user" },
  avatar: { type: String },
  isVerified: { type: Boolean, default: false },
  emailToken: { type: String },
  resetToken: { type: String },
  resetExpire: { type: Date }
}, { timestamps: true });

module.exports = mongoose.model("User", UserSchema);
