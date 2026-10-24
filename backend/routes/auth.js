const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { authenticate } = require("../middleware/auth");
const { fail, detail, userView } = require("../utils/http");

const router = express.Router();

router.post("/auth/tokens", async (req, res) => {
  const { grantType, email, password } = req.body || {};
  const details = [];
  if (grantType !== "password") details.push(detail("grantType", "UNSUPPORTED", "grantType phải là 'password'."));
  if (typeof email !== "string" || !email.trim()) details.push(detail("email", "REQUIRED", "Email phải là chuỗi không rỗng."));
  if (typeof password !== "string" || !password) details.push(detail("password", "REQUIRED", "Mật khẩu phải là chuỗi không rỗng."));
  if (details.length) return fail(res, 400, "VALIDATION_ERROR", "Dữ liệu đầu vào không hợp lệ.", details);

  const user = await User.findOne({ email: email.trim().toLowerCase(), status: { $ne: "deleted" } })
    .select("+passwordHash");
  const ok = user && await bcrypt.compare(password, user.passwordHash);
  if (!ok) return fail(res, 401, "INVALID_CREDENTIALS", "Email hoặc mật khẩu không đúng.");
  if (user.status === "locked") return fail(res, 403, "ACCOUNT_LOCKED", "Tài khoản đã bị khóa.");

  user.lastLoginAt = new Date();
  await user.save();

  const expiresIn = Number(process.env.ACCESS_TOKEN_TTL || 3600);
  const accessToken = jwt.sign({ sub: String(user._id) }, process.env.JWT_SECRET, { algorithm: "HS256", expiresIn });
  res.set("Cache-Control", "no-store");
  res.json({ tokenType: "Bearer", accessToken, expiresIn });
});

router.get("/me", authenticate, (req, res) => {
  res.json({ ...userView(req.user), permissions: [...req.permissions].sort() });
});

module.exports = router;
