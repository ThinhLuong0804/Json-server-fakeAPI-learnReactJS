const jsonServer = require("json-server");
const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();
const jwt = require("jsonwebtoken");

server.use(middlewares);
server.use(jsonServer.bodyParser);

server.post("/auth/local/register", (req, res) => {
  const { email, password, fullName } = req.body;
  const username = email;

  if (!email || !username || !password || password.length < 6 || !fullName) {
    return res.status(400).json({ message: "Invalid payload" });
  }

  // Kiểm tra email đã tồn tại trong db.json
  const users = router.db.get("users").value(); // Lấy danh sách người dùng từ db.json
  const existingUser = users.find((user) => user.email === email);

  if (existingUser) {
    return res.status(400).json({ message: "Email is already taken" });
  }

  const userId = 5; // giả lập ID người dùng
  const token = jwt.sign({ id: userId }, "your_secret_key", {
    expiresIn: "7d",
  });

  const user = {
    id: userId,
    username,
    email,
    provider: "local",
    confirmed: true,
    blocked: null,
    role: {
      id: 1,
      name: "Authenticated",
      description: "Default role given to authenticated user.",
      type: "authenticated",
      created_by: null,
      updated_by: null,
    },
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    created_by: null,
    updated_by: null,
  };

  res.json({
    jwt: token,
    user,
  });
});

server.use(router);

server.listen(3000, () => {
  console.log("JSON Server is running");
});
