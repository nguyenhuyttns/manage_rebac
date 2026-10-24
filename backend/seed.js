require("dotenv").config({ path: require("node:path").join(__dirname, ".env"), quiet: true });
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const Permission = require("./models/Permission");
const Role = require("./models/Role");
const User = require("./models/User");

const PERMISSIONS = [
  ["users:read", "Xem danh sách và chi tiết người dùng"],
  ["users:create", "Tạo người dùng"],
  ["users:update", "Sửa thông tin, khóa/mở khóa người dùng"],
  ["users:delete", "Xóa người dùng"],
  ["roles:read", "Xem vai trò và quyền của vai trò"],
  ["roles:create", "Tạo vai trò"],
  ["roles:update", "Sửa vai trò, thay bộ quyền của vai trò"],
  ["roles:delete", "Xóa vai trò"],
  ["roles:assign", "Gán / gỡ vai trò cho người dùng"],
  ["permissions:read", "Xem danh mục quyền"],
].map(([code, description]) => ({ code, resource: code.split(":")[0], action: code.split(":")[1], description }));

const ROLES = [
  { code: "super-admin", name: "Quản trị viên tối cao", isSystem: true, permissions: PERMISSIONS.map((p) => p.code) },
  { code: "user-manager", name: "Quản lý người dùng", isSystem: true, permissions: ["users:read", "users:create", "users:update", "roles:read", "roles:assign", "permissions:read"] },
  { code: "auditor", name: "Kiểm toán viên", isSystem: true, permissions: ["users:read", "roles:read", "permissions:read"] },
  { code: "member", name: "Thành viên", isSystem: true, permissions: [] },
  { code: "tro-giang", name: "Trợ giảng", description: "Hỗ trợ xem người dùng và vai trò", isSystem: false, permissions: ["users:read", "roles:read"] },
];

// Tài khoản đầu là thông tin do bạn cung cấp. Các tài khoản còn lại là dữ liệu mẫu.
// Trước khi nộp bài, thay tên/email mẫu bằng thông tin thật theo mục 1.11.
const USERS = [
  { email: "huy.nd252582m@sis.hust.edu.vn", fullName: "Nguyễn Đức Huy", password: "Admin@2026", roles: ["super-admin"] },
  { email: "manager@example.test", fullName: "Trần Minh Anh", password: "Manager@2026", roles: ["user-manager"] },
  { email: "auditor@example.test", fullName: "Lê Thu Hà", password: "Auditor@2026", roles: ["auditor"] },
  { email: "member@example.test", fullName: "Phạm Hoàng Nam", password: "Member@2026", roles: ["member"] },
  { email: "assistant@example.test", fullName: "Vũ Ngọc Linh", password: "Member@2026", roles: ["member", "tro-giang"] },
];

async function seed() {
  if (!process.env.MONGODB_URI) throw new Error("Chưa cấu hình MONGODB_URI trong backend/.env.");
  await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
  if (mongoose.connection.name !== "it4409_rbac") throw new Error("Seed chỉ chạy trên database it4409_rbac theo hướng dẫn.");

  const counts = await Promise.all([Permission.countDocuments(), Role.countDocuments(), User.countDocuments()]);
  if (counts.some((count) => count > 0) && !process.argv.includes("--reset")) {
    throw new Error("Database đã có dữ liệu. Giữ nguyên dữ liệu hiện tại. Chỉ dùng npm run seed -- --reset nếu muốn XÓA và tạo lại ba collection.");
  }

  // Kiểm tra dữ liệu và băm mật khẩu trước khi thay đổi database.
  const preparedUsers = [];
  for (const user of USERS) {
    if (user.roles.some((code) => !ROLES.some((role) => role.code === code))) throw new Error(`Vai trò seed không tồn tại: ${user.email}`);
    const passwordHash = await bcrypt.hash(user.password, 10);
    await new User({ email: user.email, fullName: user.fullName, phone: user.phone ?? null, passwordHash }).validate();
    preparedUsers.push({ ...user, passwordHash });
  }
  await Promise.all(ROLES.map((role) => new Role(role).validate()));
  await Promise.all(PERMISSIONS.map((permission) => new Permission(permission).validate()));

  if (process.argv.includes("--reset")) {
    await Promise.all([Permission.deleteMany({}), Role.deleteMany({}), User.deleteMany({})]);
  }
  await Promise.all([Permission.init(), Role.init(), User.init()]);
  await Permission.insertMany(PERMISSIONS);
  const roles = await Role.insertMany(ROLES);
  const roleId = Object.fromEntries(roles.map((role) => [role.code, role._id]));
  for (const user of preparedUsers) {
    await User.create({
      email: user.email, fullName: user.fullName, phone: user.phone ?? null,
      passwordHash: user.passwordHash, roles: user.roles.map((code) => roleId[code]),
    });
  }
  console.log(`Đã tạo ${PERMISSIONS.length} quyền, ${ROLES.length} vai trò, ${USERS.length} người dùng trong it4409_rbac.`);
}

if (require.main === module) {
  (async () => {
    try {
      await seed();
    } catch (err) {
      console.error("Seed thất bại:", err.message);
      process.exitCode = 1;
    } finally {
      await mongoose.disconnect();
    }
  })();
}

module.exports = { PERMISSIONS, ROLES, USERS };
