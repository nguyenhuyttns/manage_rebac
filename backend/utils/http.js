const mongoose = require("mongoose");

function fail(res, status, code, message, details) {
  const error = { code, message };
  if (details?.length) error.details = details;
  return res.status(status).json({ error });
}

const detail = (field, issue, message) => ({ field, issue, message });
const notAllowedFields = (body, allowed) => Object.keys(body || {})
  .filter((key) => !allowed.includes(key))
  .map((key) => detail(key, "FIELD_NOT_ALLOWED", `Trường '${key}' không được phép gửi lên endpoint này.`));
function bodyDetails(body, allowed) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return [detail("body", "INVALID_TYPE", "Body phải là một đối tượng JSON.")];
  }
  return notAllowedFields(body, allowed);
}
const isObjectId = (id) => typeof id === "string" && /^[a-f\d]{24}$/i.test(id)
  && mongoose.isValidObjectId(id);

function parsePaging(query, details) {
  const page = query.page === undefined ? 1 : Number(query.page);
  const limit = query.limit === undefined ? 10 : Number(query.limit);
  if ((query.page !== undefined && typeof query.page !== "string") || !Number.isSafeInteger(page) || page < 1 || !Number.isSafeInteger((page - 1) * limit)) details.push(detail("page", "INVALID_VALUE", "page phải là số nguyên ≥ 1 trong phạm vi phân trang hợp lệ."));
  if ((query.limit !== undefined && typeof query.limit !== "string") || !Number.isInteger(limit) || limit < 1 || limit > 100) details.push(detail("limit", "OUT_OF_RANGE", "limit phải trong khoảng 1–100."));
  return { page, limit };
}

function parseSort(raw, allowed, details) {
  const sort = {};
  if (typeof raw !== "string" || !raw.trim()) {
    details.push(detail("sort", "INVALID_VALUE", "sort phải là chuỗi tên trường hợp lệ."));
    return sort;
  }
  for (const part of String(raw).split(",").map((s) => s.trim()).filter(Boolean)) {
    const field = part.replace(/^-/, "");
    if (!allowed.includes(field)) {
      details.push(detail("sort", "FIELD_NOT_SORTABLE", `Không sắp xếp được theo '${field}'.`));
    } else {
      sort[field] = part.startsWith("-") ? -1 : 1;
    }
  }
  return sort;
}

function parseSearch(raw, details) {
  if (raw === undefined) return "";
  if (typeof raw !== "string" || raw.trim().length < 2) {
    details.push(detail("q", "INVALID_VALUE", "q phải là chuỗi có ít nhất 2 ký tự."));
    return "";
  }
  return raw.trim();
}

const escapeRegex = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const pageMeta = (page, limit, totalItems) => ({ page, limit, totalItems, totalPages: Math.max(1, Math.ceil(totalItems / limit)) });
const roleSummary = (role) => ({ id: String(role._id), code: role.code, name: role.name });
const permissionView = (permission) => ({ code: permission.code, resource: permission.resource, action: permission.action, description: permission.description });

function userView(user) {
  return {
    id: String(user._id), email: user.email, fullName: user.fullName,
    phone: user.phone, status: user.status,
    roles: (user.roles || []).filter((role) => role?.code).map(roleSummary),
    lastLoginAt: user.lastLoginAt, createdAt: user.createdAt, updatedAt: user.updatedAt,
  };
}

function roleView(role, userCount) {
  return {
    id: String(role._id), code: role.code, name: role.name, description: role.description,
    isSystem: role.isSystem, permissions: [...role.permissions], userCount,
    createdAt: role.createdAt, updatedAt: role.updatedAt,
  };
}

module.exports = { fail, detail, notAllowedFields, bodyDetails, isObjectId, parsePaging, parseSort, parseSearch, escapeRegex, pageMeta, userView, roleView, roleSummary, permissionView };
