function isTrue(value) {
  return String(value || "").trim().toLowerCase() === "true";
}

function isDatabaseEnabled() {
  const normalized = String(process.env.USE_DATABASE || "").trim().toLowerCase();

  if (["true", "1", "yes", "on"].includes(normalized)) return true;
  if (["false", "0", "no", "off"].includes(normalized)) return false;

  return Boolean(String(process.env.MONGO_URI || "").trim());
}

module.exports = {
  isTrue,
  isDatabaseEnabled
};
