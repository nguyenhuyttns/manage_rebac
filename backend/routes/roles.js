const express = require("express");
const Role = require("../models/Role");
const User = require("../models/User");
const Permission = require("../models/Permission");
const { authenticate, requirePermission } = require("../middleware/auth");
const { missingPermissions, serializeChanges } = require("../utils/rbac");
const { fail, detail, bodyDetails, isObjectId, parsePaging, parseSort, parseSearch, escapeRegex, pageMeta, roleView, permissionView } = require("../utils/http");

const router = express.Router();
router.use(serializeChanges, authenticate);
const countUsers = (roleId) => User.countDocuments({ roles: roleId, status: { $ne: "deleted" } });

async function loadRole(req, res, next) {
  const role = isObjectId(req.params.roleId) ? await Role.findById(req.params.roleId) : null;
  if (!role) return fail(res, 404, "ROLE_NOT_FOUND", "Không tìm thấy vai trò.");
  req.role = role;
  next();
}

function roleFieldDetails(body, creating = false) {
  const details = [];
  if (creating && (typeof body.code !== "string" || !/^[a-z][a-z0-9-]{2,49}$/.test(body.code.trim()))) details.push(detail("code", "INVALID_VALUE", "Mã vai trò phải có 3–50 ký tự chữ thường, số, gạch nối và bắt đầu bằng chữ."));
  if ((creating || Object.hasOwn(body, "name")) && (typeof body.name !== "string" || body.name.trim().length < 2 || body.name.trim().length > 100)) details.push(detail("name", "INVALID_VALUE", "Tên vai trò phải có từ 2 đến 100 ký tự."));
  if (Object.hasOwn(body, "description") && body.description !== null && typeof body.description !== "string") details.push(detail("description", "INVALID_TYPE", "Mô tả phải là chuỗi hoặc null."));
  return details;
}

async function checkPermissionList(permissions) {
  if (!Array.isArray(permissions) || !permissions.every((code) => typeof code === "string")) {
    return { code: "VALIDATION_ERROR", details: [detail("permissions", "INVALID_TYPE", "permissions phải là mảng mã quyền.")] };
  }
  const known = new Set((await Permission.find({ code: { $in: permissions } })).map((permission) => permission.code));
  const unknown = [...new Set(permissions)].filter((code) => !known.has(code));
  if (unknown.length) return { code: "PERMISSION_NOT_FOUND", details: unknown.map((code) => detail("permissions", "NOT_FOUND", `Quyền '${code}' không tồn tại.`)) };
  return null;
}

router.get("/", requirePermission("roles:read"), async (req, res) => {
  const details = [];
  const { page, limit } = parsePaging(req.query, details);
  const sort = parseSort(req.query.sort ?? "name", ["name", "code", "createdAt"], details);
  const search = parseSearch(req.query.q, details);
  if (details.length) return fail(res, 400, "INVALID_QUERY_PARAMETER", "Tham số truy vấn không hợp lệ.", details);
  const filter = {};
  if (search) {
    const regex = { $regex: escapeRegex(search), $options: "i" };
    filter.$or = [{ name: regex }, { code: regex }];
  }
  const [roles, totalItems] = await Promise.all([
    Role.find(filter).sort({ ...sort, _id: 1 }).skip((page - 1) * limit).limit(limit),
    Role.countDocuments(filter),
  ]);
  const data = await Promise.all(roles.map(async (role) => roleView(role, await countUsers(role._id))));
  res.json({ data, meta: pageMeta(page, limit, totalItems) });
});

router.post("/", requirePermission("roles:create"), async (req, res) => {
  const body = req.body;
  const details = bodyDetails(body, ["code", "name", "description", "permissions"]);
  if (!body || typeof body !== "object" || Array.isArray(body)) return fail(res, 400, "VALIDATION_ERROR", "Dữ liệu đầu vào không hợp lệ.", details);
  details.push(...roleFieldDetails(body, true));
  if (details.length) return fail(res, 400, "VALIDATION_ERROR", "Dữ liệu đầu vào không hợp lệ.", details);
  const permissions = body.permissions === undefined ? [] : body.permissions;
  const error = await checkPermissionList(permissions);
  if (error) return fail(res, 400, error.code, "Danh sách quyền không hợp lệ.", error.details);
  if (missingPermissions(permissions, req.permissions).length) return fail(res, 403, "PRIVILEGE_ESCALATION", "Không thể cấp quyền mà bạn không có.");
  if (await Role.exists({ code: body.code.trim() })) return fail(res, 409, "ROLE_CODE_EXISTS", "Mã vai trò đã tồn tại.");
  const role = await Role.create({ code: body.code, name: body.name, description: body.description ?? null, permissions: [...new Set(permissions)] });
  res.status(201).location(`${req.baseUrl}/${role._id}`).json(roleView(role, 0));
});

router.get("/:roleId", requirePermission("roles:read"), loadRole, async (req, res) => {
  res.json(roleView(req.role, await countUsers(req.role._id)));
});

router.patch("/:roleId", requirePermission("roles:update"), loadRole, async (req, res) => {
  const body = req.body;
  const details = bodyDetails(body, ["name", "description"]);
  if (!body || typeof body !== "object" || Array.isArray(body)) return fail(res, 400, "VALIDATION_ERROR", "Dữ liệu đầu vào không hợp lệ.", details);
  details.push(...roleFieldDetails(body));
  if (details.length) return fail(res, 400, "VALIDATION_ERROR", "Dữ liệu đầu vào không hợp lệ.", details);
  for (const key of ["name", "description"]) if (Object.hasOwn(body, key)) req.role[key] = body[key];
  await req.role.save();
  res.json(roleView(req.role, await countUsers(req.role._id)));
});

router.delete("/:roleId", requirePermission("roles:delete"), loadRole, async (req, res) => {
  if (req.role.isSystem) return fail(res, 409, "SYSTEM_ROLE_PROTECTED", "Không thể xóa vai trò hệ thống.");
  if (await countUsers(req.role._id)) return fail(res, 409, "ROLE_IN_USE", "Vai trò đang được gán cho người dùng.");
  await req.role.deleteOne();
  res.status(204).end();
});

router.get("/:roleId/permissions", requirePermission("roles:read"), loadRole, async (req, res) => {
  const permissions = await Permission.find({ code: { $in: req.role.permissions } }).sort({ resource: 1, code: 1 });
  const data = permissions.map(permissionView);
  res.json({ data, meta: { totalItems: data.length } });
});

router.put("/:roleId/permissions", requirePermission("roles:update"), loadRole, async (req, res) => {
  const details = bodyDetails(req.body, ["permissions"]);
  if (details.length) return fail(res, 400, "VALIDATION_ERROR", "Dữ liệu đầu vào không hợp lệ.", details);
  const error = await checkPermissionList(req.body.permissions);
  if (error) return fail(res, 400, error.code, "Danh sách quyền không hợp lệ.", error.details);
  if (req.role.isSystem) return fail(res, 409, "SYSTEM_ROLE_PROTECTED", "Không thể thay bộ quyền của vai trò hệ thống.");
  const nextPermissions = [...new Set(req.body.permissions)];
  // Kiểm tra cả quyền thêm vào lẫn quyền bị gỡ, giữ được quyền ngoài phạm vi nếu không đổi.
  const changed = [...new Set([...req.role.permissions, ...nextPermissions])]
    .filter((code) => req.role.permissions.includes(code) !== nextPermissions.includes(code));
  if (missingPermissions(changed, req.permissions).length) return fail(res, 403, "PRIVILEGE_ESCALATION", "Không thể thêm hoặc gỡ quyền mà bạn không có.");
  req.role.permissions = nextPermissions;
  await req.role.save();
  res.json(roleView(req.role, await countUsers(req.role._id)));
});

module.exports = router;
