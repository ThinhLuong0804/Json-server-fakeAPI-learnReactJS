const jsonServer = require("json-server");
const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();
const jwt = require("jsonwebtoken");

const SECRET_KEY = "your_secret_key"; // Khóa bí mật cho JWT
const TOKEN_EXPIRATION = "7d"; // Thời gian hết hạn của token

server.use(middlewares);
server.use(jsonServer.bodyParser);

// Middleware xác thực JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res
      .status(401)
      .json({ message: "Access token is missing or invalid" });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
};

// Đăng ký người dùng
server.post("/auth/local/register", (req, res) => {
  const { email, password, fullName } = req.body;
  const username = email;

  if (!email || !username || !password || password.length < 6 || !fullName) {
    return res.status(400).json({ message: "Invalid payload" });
  }

  const users = router.db.get("users").value();
  const existingUser = users.find((user) => user.email === email);

  if (existingUser) {
    return res.status(400).json({ message: "Email is already taken" });
  }

  const userId = users.length
    ? Math.max(...users.map((user) => user.id)) + 1
    : 1;
  const token = jwt.sign({ id: userId }, SECRET_KEY, {
    expiresIn: TOKEN_EXPIRATION,
  });

  const user = {
    id: userId,
    username,
    email,
    password, // Trong thực tế, cần hash mật khẩu trước khi lưu
    provider: "local",
    confirmed: true,
    blocked: null,
    role: {
      id: 1,
      name: "Authenticated",
      description: "Default role given to authenticated user.",
      type: "authenticated",
    },
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  // Lưu người dùng mới vào db.json
  router.db.get("users").push(user).write();

  res.json({
    jwt: token,
    user,
  });
});

// Đăng nhập người dùng
server.post("/auth/local/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Invalid payload" });
  }

  const users = router.db.get("users").value();
  const existingUser = users.find((user) => user.email === email);

  if (!existingUser) {
    return res.status(400).json({ message: "User not found" });
  }

  if (existingUser.password !== password) {
    return res.status(400).json({ message: "Invalid password" });
  }

  const token = jwt.sign({ id: existingUser.id }, SECRET_KEY, {
    expiresIn: TOKEN_EXPIRATION,
  });

  res.json({
    jwt: token,
    user: existingUser,
  });
});

// Route được bảo vệ
server.get("/protected", authenticateToken, (req, res) => {
  res.json({
    message: "You have accessed a protected route!",
    user: req.user,
  });
});

// Lấy thông tin người dùng hiện tại
server.get("/user/me", authenticateToken, (req, res) => {
  const users = router.db.get("users").value();
  const currentUser = users.find((user) => user.id === req.user.id);

  if (!currentUser) {
    return res.status(404).json({ message: "User not found" });
  }

  res.json(currentUser);
});

server.use(router);

server.listen(3000, () => {
  console.log("JSON Server is running on http://localhost:3000");
});
