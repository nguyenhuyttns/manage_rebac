const express = require("express");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const Role = require("../models/Role");
const { authenticate, requirePermission } = require("../middleware/auth");
const { missingPermissions, isLastSuperAdmin, serializeChanges } = require("../utils/rbac");
const { fail, detail, bodyDetails, isObjectId, parsePaging, parseSort, parseSearch, escapeRegex, pageMeta, userView, roleSummary } = require("../utils/http");

const router = express.Router();
router.use(serializeChanges, authenticate);
const PASSWORD_RE = /^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;

async function loadUser(req, res, next) {
  const user = isObjectId(req.params.userId)
    ? await User.findOne({ _id: req.params.userId, status: { $ne: "deleted" } }).populate("roles") : null;
  if (!user) return fail(res, 404, "USER_NOT_FOUND", "Không tìm thấy người dùng.");
  req.target = user;
  next();
}

async function loadRole(req, res, next) {
  const role = isObjectId(req.params.roleId) ? await Role.findById(req.params.roleId) : null;
  if (!role) return fail(res, 404, "ROLE_NOT_FOUND", "Không tìm thấy vai trò.");
  req.role = role;
  next();
}

function userFieldDetails(body, creating = false) {
  const details = [];
  if (creating || Object.hasOwn(body, "email")) {
    if (typeof body.email !== "string" || !/^\S+@\S+\.\S+$/.test(body.email.trim())) details.push(detail("email", "INVALID_VALUE", "Email không đúng định dạng."));
  }
  if (creating || Object.hasOwn(body, "fullName")) {
    if (typeof body.fullName !== "string" || body.fullName.trim().length < 2 || body.fullName.trim().length > 100) details.push(detail("fullName", "INVALID_VALUE", "Họ tên phải có từ 2 đến 100 ký tự."));
  }
  if (Object.hasOwn(body, "phone") && body.phone !== null && (typeof body.phone !== "string" || !/^\+[1-9]\d{7,14}$/.test(body.phone))) details.push(detail("phone", "INVALID_VALUE", "Số điện thoại phải theo định dạng E.164, ví dụ +84912345678."));
  return details;
}

router.get("/", requirePermission("users:read"), async (req, res) => {
  const query = req.query;
  const details = [];
  const { page, limit } = parsePaging(query, details);
  const sort = parseSort(query.sort ?? "-createdAt", ["fullName", "email", "createdAt", "lastLoginAt"], details);
  const search = parseSearch(query.q, details);
  if (query.status !== undefined && !["active", "locked"].includes(query.status)) details.push(detail("status", "INVALID_VALUE", "status phải là active hoặc locked."));
  if (query.roleId !== undefined && !isObjectId(query.roleId)) details.push(detail("roleId", "INVALID_VALUE", "roleId phải là ObjectId hợp lệ."));
  if (details.length) return fail(res, 400, "INVALID_QUERY_PARAMETER", "Tham số truy vấn không hợp lệ.", details);

  const filter = { status: query.status || { $ne: "deleted" } };
  if (query.roleId) filter.roles = query.roleId;
  if (search) {
    const regex = { $regex: escapeRegex(search), $options: "i" };
    filter.$or = [{ fullName: regex }, { email: regex }];
  }
  const [items, totalItems] = await Promise.all([
    User.find(filter).sort({ ...sort, _id: 1 }).skip((page - 1) * limit).limit(limit).populate("roles"),
    User.countDocuments(filter),
  ]);
  res.json({ data: items.map(userView), meta: pageMeta(page, limit, totalItems) });
});

router.post("/", requirePermission("users:create"), async (req, res) => {
  const body = req.body;
  const details = bodyDetails(body, ["email", "fullName", "phone", "password", "roleIds"]);
  if (!body || typeof body !== "object" || Array.isArray(body)) return fail(res, 400, "VALIDATION_ERROR", "Dữ liệu đầu vào không hợp lệ.", details);
  details.push(...userFieldDetails(body, true));
  if (typeof body.password !== "string" || !body.password) details.push(detail("password", "REQUIRED", "Mật khẩu phải là chuỗi không rỗng."));
  else if (!PASSWORD_RE.test(body.password)) details.push(detail("password", "WEAK_PASSWORD", "Mật khẩu tối thiểu 8 ký tự, có chữ hoa, chữ số và ký tự đặc biệt."));
  if (Object.hasOwn(body, "roleIds") && (!Array.isArray(body.roleIds) || !body.roleIds.every(isObjectId))) details.push(detail("roleIds", "INVALID_VALUE", "roleIds phải là mảng ObjectId hợp lệ."));
  if (details.length) return fail(res, 400, "VALIDATION_ERROR", "Dữ liệu đầu vào không hợp lệ.", details);

  if (Object.hasOwn(body, "roleIds") && !req.permissions.has("roles:assign")) return fail(res, 403, "FORBIDDEN", "Gán vai trò khi tạo người dùng cần quyền roles:assign.");
  const roleIds = [...new Set((body.roleIds || []).map((id) => id.toLowerCase()))];
  const roles = roleIds.length ? await Role.find({ _id: { $in: roleIds } }) : await Role.find({ code: "member" });
  if (roleIds.length && roles.length !== roleIds.length) return fail(res, 400, "ROLE_NOT_FOUND", "Có vai trò không tồn tại trong roleIds.");
  if (missingPermissions(roles.flatMap((role) => role.permissions), req.permissions).length) return fail(res, 403, "PRIVILEGE_ESCALATION", "Không thể gán vai trò có quyền vượt quá quyền của bạn.");
  if (!roles.length) throw new Error("Chưa seed vai trò member.");

  const email = body.email.trim().toLowerCase();
  if (await User.exists({ email })) return fail(res, 409, "EMAIL_ALREADY_EXISTS", "Email đã được sử dụng.");
  const user = await User.create({
    email, fullName: body.fullName, phone: body.phone ?? null,
    passwordHash: await bcrypt.hash(body.password, 10), roles: roles.map((role) => role._id),
  });
  await user.populate("roles");
  res.status(201).location(`${req.baseUrl}/${user._id}`).json(userView(user));
});

router.get("/:userId", requirePermission("users:read"), loadUser, (req, res) => res.json(userView(req.target)));

router.patch("/:userId", requirePermission("users:update"), loadUser, async (req, res) => {
  const body = req.body;
  const allowed = ["fullName", "phone", "email", "status"];
  const details = bodyDetails(body, allowed);
  if (!body || typeof body !== "object" || Array.isArray(body)) return fail(res, 400, "VALIDATION_ERROR", "Dữ liệu đầu vào không hợp lệ.", details);
  details.push(...userFieldDetails(body));
  if (Object.hasOwn(body, "status") && !["active", "locked"].includes(body.status)) details.push(detail("status", "INVALID_VALUE", "status phải là active hoặc locked."));
  if (details.length) return fail(res, 400, "VALIDATION_ERROR", "Dữ liệu đầu vào không hợp lệ.", details);

  if (body.status === "locked") {
    if (String(req.target._id) === String(req.user._id)) return fail(res, 403, "SELF_ACTION_FORBIDDEN", "Không thể tự khóa tài khoản của mình.");
    if (await isLastSuperAdmin(req.target)) return fail(res, 409, "LAST_SUPER_ADMIN", "Phải còn ít nhất một super-admin đang hoạt động.");
  }
  if (Object.hasOwn(body, "email") && await User.exists({ email: body.email.trim().toLowerCase(), _id: { $ne: req.target._id } })) return fail(res, 409, "EMAIL_ALREADY_EXISTS", "Email đã được sử dụng.");
  // Chỉ gán trường được gửi, giữ nguyên các trường còn lại.
  for (const key of allowed) if (Object.hasOwn(body, key)) req.target[key] = body[key];
  await req.target.save();
  res.json(userView(req.target));
});

router.delete("/:userId", requirePermission("users:delete"), loadUser, async (req, res) => {
  if (String(req.target._id) === String(req.user._id)) return fail(res, 403, "SELF_ACTION_FORBIDDEN", "Không thể tự xóa tài khoản của mình.");
  if (await isLastSuperAdmin(req.target)) return fail(res, 409, "LAST_SUPER_ADMIN", "Phải còn ít nhất một super-admin đang hoạt động.");
  req.target.status = "deleted";
  await req.target.save();
  res.status(204).end();
});

router.get("/:userId/roles", requirePermission("users:read"), loadUser, (req, res) => {
  const data = req.target.roles.filter(Boolean).map(roleSummary);
  res.json({ data, meta: { totalItems: data.length } });
});

router.put("/:userId/roles/:roleId", requirePermission("roles:assign"), loadUser, loadRole, async (req, res) => {
  if (missingPermissions(req.role.permissions, req.permissions).length) return fail(res, 403, "PRIVILEGE_ESCALATION", "Không thể gán vai trò có quyền vượt quá quyền của bạn.");
  await User.updateOne({ _id: req.target._id }, { $addToSet: { roles: req.role._id } });
  res.status(204).end();
});

router.delete("/:userId/roles/:roleId", requirePermission("roles:assign"), loadUser, loadRole, async (req, res) => {
  if (String(req.target._id) === String(req.user._id)) return fail(res, 403, "SELF_ACTION_FORBIDDEN", "Không thể tự gỡ vai trò của mình.");
  if (missingPermissions(req.role.permissions, req.permissions).length) return fail(res, 403, "PRIVILEGE_ESCALATION", "Không thể gỡ vai trò có quyền vượt quá quyền của bạn.");
  if (req.role.code === "super-admin" && await isLastSuperAdmin(req.target)) return fail(res, 409, "LAST_SUPER_ADMIN", "Phải còn ít nhất một super-admin đang hoạt động.");
  await User.updateOne({ _id: req.target._id }, { $pull: { roles: req.role._id } });
  res.status(204).end();
});

module.exports = router;
