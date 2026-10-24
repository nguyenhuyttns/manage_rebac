require("dotenv").config({ path: require("node:path").join(__dirname, ".env"), quiet: true });
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const { fail, detail } = require("./utils/http");

const app = express();
const allowed = (process.env.CORS_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => cb(null, !origin || allowed.includes(origin)),
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
  allowedHeaders: ["Authorization", "Content-Type"],
  exposedHeaders: ["Location"],
}));
app.use(express.json({ limit: "100kb" }));
app.use("/api/v1", require("./routes/auth"));
app.use("/api/v1/users", require("./routes/users"));
app.use("/api/v1/roles", require("./routes/roles"));
app.use("/api/v1/permissions", require("./routes/permissions"));
app.use((req, res) => fail(res, 404, "ENDPOINT_NOT_FOUND", `Không có endpoint ${req.method} ${req.path}.`));

app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return fail(res, 400, "MALFORMED_JSON", "Body không phải JSON hợp lệ.");
  if (err.type === "entity.too.large") return fail(res, 413, "PAYLOAD_TOO_LARGE", "Body vượt quá giới hạn 100kb.");
  if (err.name === "ValidationError") {
    const details = Object.values(err.errors).map((e) => detail(e.path, e.kind === "required" ? "REQUIRED" : "INVALID_VALUE", e.message));
    return fail(res, 400, "VALIDATION_ERROR", "Dữ liệu đầu vào không hợp lệ.", details);
  }
  if (err.code === 11000) {
    const emailDuplicate = Boolean(err.keyPattern?.email || Object.hasOwn(err.keyValue || {}, "email"));
    return emailDuplicate
      ? fail(res, 409, "EMAIL_ALREADY_EXISTS", "Email đã được sử dụng.")
      : fail(res, 409, "ROLE_CODE_EXISTS", "Mã vai trò đã tồn tại.");
  }
  console.error(err);
  fail(res, 500, "INTERNAL_ERROR", "Đã có lỗi phía server. Vui lòng thử lại sau.");
});

async function start() {
  if (!process.env.MONGODB_URI) throw new Error("Chưa cấu hình MONGODB_URI trong backend/.env.");
  if (!process.env.JWT_SECRET) throw new Error("Chưa cấu hình JWT_SECRET trong backend/.env.");
  const ttl = Number(process.env.ACCESS_TOKEN_TTL || 3600);
  if (!Number.isInteger(ttl) || ttl <= 0) throw new Error("ACCESS_TOKEN_TTL phải là số nguyên dương.");
  await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
  const port = Number(process.env.PORT || 3001);
  return new Promise((resolve, reject) => {
    const server = app.listen(port, (err) => {
      if (err) return reject(err);
      console.log(`Đã kết nối MongoDB. Server: http://localhost:${port}/api/v1`);
      resolve(server);
    });
  });
}

if (require.main === module) {
  (async () => {
    try {
      await start();
    } catch (err) {
      console.error("Không khởi động được backend:", err.message);
      await mongoose.disconnect();
      process.exitCode = 1;
    }
  })();
}

module.exports = { app, start };
