const jwt = require("jsonwebtoken");
const User = require("../models/User");
// Đăng ký model Role trước khi populate, kể cả khi chưa có API role ở Bước 2.
require("../models/Role");
const { fail, isObjectId } = require("../utils/http");

async function authenticate(req, res, next) {
  const match = (req.get("Authorization") || "").match(/^Bearer\s+(.+)$/i);
  if (!match) return fail(res, 401, "UNAUTHENTICATED", "Thiếu access token. Gửi header Authorization: Bearer <token>.");

  let payload;
  try {
    payload = jwt.verify(match[1], process.env.JWT_SECRET, { algorithms: ["HS256"] });
  } catch (err) {
    return err.name === "TokenExpiredError"
      ? fail(res, 401, "TOKEN_EXPIRED", "Access token đã hết hạn. Vui lòng đăng nhập lại.")
      : fail(res, 401, "INVALID_TOKEN", "Access token không hợp lệ.");
  }
  if (!isObjectId(payload.sub)) return fail(res, 401, "INVALID_TOKEN", "Access token không hợp lệ.");

  // Đọc lại user và role ở MỖI request, không lấy quyền từ token.
  const user = await User.findById(payload.sub).populate("roles");
  if (!user || user.status !== "active") return fail(res, 401, "INVALID_TOKEN", "Phiên đăng nhập không còn hiệu lực.");

  req.user = user;
  req.permissions = new Set(user.roles.filter(Boolean).flatMap((role) => role.permissions));
  next();
}

function requirePermission(...codes) {
  return (req, res, next) => {
    const missing = codes.filter((code) => !req.permissions.has(code));
    if (missing.length) return fail(res, 403, "FORBIDDEN", `Bạn không có quyền thực hiện thao tác này (cần: ${missing.join(", ")}).`);
    next();
  };
}

module.exports = { authenticate, requirePermission };
