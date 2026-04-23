function isTrue(value) {
  return String(value || "").trim().toLowerCase() === "true";
}

module.exports = {
  isTrue
};
