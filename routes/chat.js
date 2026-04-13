const express = require("express");

const router = express.Router();

const INTENTS = [
  {
    keywords: ["hello", "hi", "hey", "good morning", "good evening"],
    reply: "Hello! How can I help you today?"
  },
  {
    keywords: ["leave", "vacation", "holiday", "time off"],
    reply: "You can request leave from the HR portal. Go to HR -> Leave Requests and submit your dates."
  },
  {
    keywords: ["benefit", "insurance", "salary", "payroll"],
    reply: "For benefits and payroll details, open the HR section in your employee dashboard."
  },
  {
    keywords: ["onboarding", "training", "joining", "new hire"],
    reply: "Onboarding includes account setup, policy walkthrough, and team introductions."
  },
  {
    keywords: ["profile", "account", "update profile", "avatar"],
    reply: "You can update your name and profile photo from the Profile page."
  },
  {
    keywords: ["admin", "users", "user list"],
    reply: "Admin users can open the Admin section to review all registered users."
  },
  {
    keywords: ["reset password", "forgot password", "password"],
    reply: "Use the Forgot Password option on login to receive a reset link."
  }
];

function getBotReply(message) {
  const q = String(message || "").toLowerCase().trim();

  if (!q) {
    return "Please type a question so I can help.";
  }

  for (const intent of INTENTS) {
    if (intent.keywords.some((keyword) => q.includes(keyword))) {
      return intent.reply;
    }
  }

  return "I can help with onboarding, leave, benefits, profile updates, and account questions.";
}

router.post("/", (req, res) => {
  const { message } = req.body || {};

  if (!message || !String(message).trim()) {
    return res.status(400).json({
      ok: false,
      reply: "Message is required."
    });
  }

  return res.json({
    ok: true,
    reply: getBotReply(message)
  });
});

module.exports = router;
