const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: "user" },
  avatar: { type: String },
  phone: { type: String, trim: true, default: "" },
  jobTitle: { type: String, trim: true, default: "" },
  department: { type: String, trim: true, default: "" },
  location: { type: String, trim: true, default: "" },
  employeeId: { type: String, trim: true, default: "" },
  managerName: { type: String, trim: true, default: "" },
  joinDate: { type: Date },
  bio: { type: String, trim: true, default: "" },
  skills: { type: String, trim: true, default: "" },
  linkedinUrl: { type: String, trim: true, default: "" },
  isVerified: { type: Boolean, default: false },
  emailToken: { type: String },
  resetToken: { type: String },
  resetExpire: { type: Date },
  resetRequestedAt: { type: Date }
}, { timestamps: true });

module.exports = mongoose.model("User", UserSchema);
