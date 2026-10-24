const mongoose = require("mongoose");

const roleSchema = new mongoose.Schema({
  code: {
    type: String, required: true, unique: true, trim: true, immutable: true,
    match: [/^[a-z][a-z0-9-]{2,49}$/, "Mã vai trò phải có 3–50 ký tự chữ thường, số, gạch nối và bắt đầu bằng chữ."],
  },
  name: { type: String, required: true, trim: true, minlength: 2, maxlength: 100 },
  description: { type: String, default: null },
  isSystem: { type: Boolean, default: false, immutable: true },
  permissions: { type: [String], default: [] },
}, { timestamps: true });

module.exports = mongoose.model("Role", roleSchema);
