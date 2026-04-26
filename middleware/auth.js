const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ msg: "No token" });

  const [scheme, token] = authHeader.split(" ");
  if (scheme !== "Bearer") {
    return res.status(401).json({ msg: "Invalid authorization header" });
  }
  if (!token) return res.status(401).json({ msg: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.user;
    next();
  } catch (err) {
    if (err && err.name === "TokenExpiredError") {
      return res.status(401).json({ msg: "Session expired. Please login again." });
    }
    return res.status(401).json({ msg: "Token invalid" });
  }
};
