const express = require("express");
const Permission = require("../models/Permission");
const { authenticate, requirePermission } = require("../middleware/auth");
const { fail, detail, permissionView } = require("../utils/http");

const router = express.Router();
router.use(authenticate);

router.get("/", requirePermission("permissions:read"), async (req, res) => {
  if (req.query.resource !== undefined && (typeof req.query.resource !== "string" || !req.query.resource.trim())) {
    return fail(res, 400, "INVALID_QUERY_PARAMETER", "resource phải là chuỗi không rỗng.", [detail("resource", "INVALID_VALUE", "resource phải là chuỗi không rỗng.")]);
  }
  const filter = req.query.resource === undefined ? {} : { resource: req.query.resource.trim() };
  const data = (await Permission.find(filter).sort({ resource: 1, code: 1 })).map(permissionView);
  res.json({ data, meta: { totalItems: data.length } });
});

module.exports = router;
