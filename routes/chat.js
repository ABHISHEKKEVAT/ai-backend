const express = require("express");
const jwt = require("jsonwebtoken");

const router = express.Router();

const INTENTS = [
  {
    keywords: ["hello", "hi", "hey", "good morning", "good evening"],
    reply:
      "Hello! I am your Employee Assistant.\nI can help with leave, payroll, onboarding, IT support, policies, and profile updates."
  },
  {
    keywords: [
      "leave",
      "vacation",
      "holiday",
      "time off",
      "sick leave",
      "casual leave",
      "paid leave",
      "leave balance"
    ],
    reply:
      "To request leave:\n1) Open HR -> Leave Requests\n2) Select leave type and dates\n3) Submit for manager approval"
  },
  {
    keywords: ["benefit", "benefits", "insurance", "salary", "payroll", "payslip", "ctc", "compensation"],
    reply:
      "For payroll and benefits:\n1) Open HR -> Payroll/Benefits\n2) Check payslips and insurance details\n3) Contact HR if any deduction looks incorrect"
  },
  {
    keywords: ["onboarding", "training", "joining", "new hire", "orientation", "welcome kit", "induction"],
    reply:
      "Onboarding checklist:\n1) Complete profile and documents\n2) Finish mandatory trainings\n3) Meet your manager/team and review role goals"
  },
  {
    keywords: ["attendance", "timesheet", "check in", "check out", "work hours", "late mark"],
    reply:
      "You can manage attendance in Attendance/Timesheet.\nIf entries are missing, add or correct them before payroll cutoff."
  },
  {
    keywords: ["remote work", "wfh", "work from home", "hybrid", "office days"],
    reply:
      "For WFH/hybrid:\n1) Submit request in HR portal\n2) Select dates/reason\n3) Wait for manager approval"
  },
  {
    keywords: ["reimbursement", "expense", "travel claim", "bill", "invoice", "claim"],
    reply:
      "For reimbursement:\n1) Open Finance -> Expenses\n2) Add claim with receipt/invoice\n3) Submit for finance approval"
  },
  {
    keywords: ["it support", "laptop", "email issue", "vpn", "software access", "access request"],
    reply:
      "For IT support, raise a Helpdesk ticket with:\n- issue summary\n- priority\n- screenshot/error message\nThis helps faster resolution."
  },
  {
    keywords: ["policy", "code of conduct", "hr policy", "notice period", "probation"],
    reply:
      "Company policies are in the HR Knowledge Base.\nYou can check sections like Code of Conduct, Probation, Notice Period, and Separation."
  },
  {
    keywords: ["holiday calendar", "public holiday", "company holiday", "festival holiday"],
    reply:
      "Holiday calendar is available in HR -> Holidays.\nYou can also sync/export it to your personal calendar."
  },
  {
    keywords: ["manager", "approval", "approver", "reporting manager", "escalation"],
    reply:
      "For approvals:\n1) Open Requests -> Pending Approvals\n2) Check current approver/manager\n3) Escalate to HR/Admin if delayed"
  },
  {
    keywords: ["performance", "review", "goal", "kpi", "appraisal", "promotion"],
    reply:
      "Performance and appraisal are under the Performance section.\nYou can review goals, KPI progress, and cycle timelines there."
  },
  {
    keywords: ["profile", "account", "update profile", "avatar"],
    reply:
      "Go to Profile page to update your name, avatar, and account details."
  },
  {
    keywords: ["admin", "users", "user list", "roles", "permissions"],
    reply:
      "Admin users can open the Admin section to review users, roles, and access permissions."
  },
  {
    keywords: ["reset password", "forgot password", "password", "change password", "login issue", "cannot login"],
    reply:
      "If you cannot log in:\n1) Open Request Password Reset\n2) Admin verifies your account and resets password\n3) Log in again using the new password from admin"
  },
  {
    keywords: ["document", "offer letter", "experience letter", "salary certificate", "id card"],
    reply:
      "Request documents from HR -> Documents.\nCommon requests: Offer Letter, Experience Letter, Salary Certificate, ID Card."
  }
];

const STARTER_PROMPTS = [
  "How do I apply for leave?",
  "Where can I download my payslip?",
  "How do I reset my password?",
  "Where are company policies?"
];

function normalizeText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function scoreIntent(query, intent) {
  let score = 0;

  for (const keyword of intent.keywords) {
    const k = normalizeText(keyword);
    if (!k) continue;

    if (query.includes(k)) {
      score += Math.min(3, k.split(" ").length);
    }
  }

  return score;
}

function getRoleFromRequest(req) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";

  if (!token) return "guest";

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded?.user?.role || "user";
  } catch (err) {
    return "guest";
  }
}

function getRoleAwareReply(baseReply, role, query) {
  const isAdminQuery = ["admin", "users", "permissions", "roles"].some((k) => query.includes(k));

  if (isAdminQuery && role !== "admin") {
    return `${baseReply}\nNote: Admin features are visible only for admin accounts.`;
  }

  if (role === "admin" && isAdminQuery) {
    return `${baseReply}\nAdmin tip: You can review users from Admin -> User List and verify role-based access.`;
  }

  return baseReply;
}

function getBotReply(message, role = "guest") {
  const q = normalizeText(message);

  if (!q) {
    return "Please type a question so I can help.";
  }

  if (["help", "start", "menu", "options", "new", "first day"].some((k) => q.includes(k))) {
    const rolePrompt =
      role === "admin"
        ? "\n- How do I manage users and roles?"
        : "\n- How can I contact admin support?";

    return `Welcome! You can ask me things like:\n- ${STARTER_PROMPTS.join("\n- ")}${rolePrompt}`;
  }

  let bestIntent = null;
  let bestScore = 0;

  for (const intent of INTENTS) {
    const score = scoreIntent(q, intent);
    if (score > bestScore) {
      bestScore = score;
      bestIntent = intent;
    }
  }

  if (bestIntent && bestScore > 0) {
    return getRoleAwareReply(bestIntent.reply, role, q);
  }

  const roleFallback =
    role === "admin"
      ? "\n- How do I manage users and role permissions?"
      : "\n- How do I raise a support request?";

  return `I did not fully understand that yet, but I can help with leave, payroll, onboarding, attendance, IT support, policies, and account help.\nTry asking:\n- ${STARTER_PROMPTS.join("\n- ")}${roleFallback}`;
}

router.post("/", (req, res) => {
  const { message } = req.body || {};
  const role = getRoleFromRequest(req);

  if (!message || !String(message).trim()) {
    return res.status(400).json({
      ok: false,
      reply: "Message is required."
    });
  }

  return res.json({
    ok: true,
    reply: getBotReply(message, role),
    role
  });
});

module.exports = router;
