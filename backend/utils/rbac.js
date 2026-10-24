const Role = require("../models/Role");
const User = require("../models/User");

const missingPermissions = (codes, myPermissions) => [...new Set(codes)].filter((code) => !myPermissions.has(code));

// Tuần tự hóa các request thay đổi RBAC trong server này: hai request đồng thời
// không được cùng vượt qua kiểm tra "admin cuối cùng" hoặc "role đang dùng".
let pendingChange = Promise.resolve();
async function serializeChanges(req, res, next) {
  if (!["POST", "PATCH", "PUT", "DELETE"].includes(req.method)) return next();
  const previous = pendingChange;
  let release;
  pendingChange = new Promise((resolve) => { release = resolve; });
  await previous;
  if (res.destroyed) return release();
  res.once("finish", release);
  res.once("close", release);
  next();
}

async function isLastSuperAdmin(user) {
  if (user.status !== "active") return false;
  const superAdmin = await Role.findOne({ code: "super-admin" });
  if (!superAdmin || !user.roles.some((role) => String(role._id || role) === String(superAdmin._id))) return false;
  const others = await User.countDocuments({ _id: { $ne: user._id }, status: "active", roles: superAdmin._id });
  return others === 0;
}

module.exports = { missingPermissions, isLastSuperAdmin, serializeChanges };
