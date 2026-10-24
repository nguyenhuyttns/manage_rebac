const mongoose = require("mongoose");

const permissionSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  resource: { type: String, required: true },
  action: { type: String, required: true },
  description: { type: String, default: "" },
});

module.exports = mongoose.model("Permission", permissionSchema);
