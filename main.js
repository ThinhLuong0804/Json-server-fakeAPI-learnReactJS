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

// API phân trang và sắp xếp sản phẩm
server.get("/products", (req, res) => {
  const page = parseInt(req.query._page, 10) || 1; // Chuyển page thành số nguyên
  const limit = parseInt(req.query._limit, 10) || 10; // Chuyển limit thành số nguyên
  const sortField = req.query._sort || "id"; // Trường để sắp xếp, mặc định là "id"
  const sortOrder = req.query._order === "DESC" ? -1 : 1; // Thứ tự sắp xếp (ASC/DESC)
  const categoryId = req.query.categoryId || null; // Lọc theo categoryId

  // Lọc theo giá
  const filters = {
    salePrice_gte: isNaN(parseFloat(req.query.salePrice_gte))
      ? 0
      : parseFloat(req.query.salePrice_gte),
    salePrice_lte: isNaN(parseFloat(req.query.salePrice_lte))
      ? Infinity
      : parseFloat(req.query.salePrice_lte),
  };

  try {
    let products = router.db.get("products").value(); // Lấy tất cả sản phẩm

    // Nếu có tham số categoryId, lọc sản phẩm theo categoryId
    if (categoryId) {
      products = products.filter(
        (product) => product.categoryId === categoryId
      );
    }

    // Lọc sản phẩm theo giá
    products = products.filter((product) => {
      const isPriceInRange =
        product.salePrice >= filters.salePrice_gte &&
        product.salePrice <= filters.salePrice_lte;
      return isPriceInRange;
    });

    // Lọc sản phẩm theo isPromotion nếu được yêu cầu
    if (req.query.isPromotion !== undefined) {
      const isPromotionFilter = req.query.isPromotion === "true";
      products = products.filter(
        (product) => product.isPromotion === isPromotionFilter
      );
    }

    // Lọc sản phẩm theo isFreeShip nếu được yêu cầu (chỉ lọc nếu isFreeShip được cung cấp)
    if (req.query.isFreeShip !== undefined) {
      const isFreeShipFilter = req.query.isFreeShip === "true";
      products = products.filter(
        (product) => product.isFreeShip === isFreeShipFilter
      );
    }

    // Sắp xếp sản phẩm nếu có tham số _sort
    if (sortField) {
      products.sort((a, b) => {
        if (a[sortField] < b[sortField]) return -1 * sortOrder;
        if (a[sortField] > b[sortField]) return 1 * sortOrder;
        return 0;
      });
    }

    // Tính toán phân trang
    const total = products.length;
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;
    const paginatedProducts = products.slice(startIndex, endIndex);

    res.json({
      data: paginatedProducts,
      pagination: {
        total,
        page,
        limit,
      },
    });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

// Lấy chi tiết sản phẩm
server.get("/products/:id", (req, res) => {
  const { id } = req.params;
  const product = router.db
    .get("products")
    .find({ id: parseInt(id, 10) }) // Chuyển id sang số nguyên để so sánh
    .value();

  if (!product) {
    return res.status(404).json({ message: "Product not found" });
  }

  res.json(product);
});

// Lấy danh sách danh mục sảnh phẩm
server.get("/categories", (req, res) => {
  const categories = router.db.get("categories").value();
  res.json(categories);
});

// Lấy sản phẩm theo danh mục
server.get("/categories/:id/products", (req, res) => {
  const { id } = req.params;
  const categoryId = parseInt(id, 10); // Chuyển id danh mục sang số nguyên
  const products = router.db
    .get("products")
    .filter((product) => product.categoryId === categoryId) // Lọc theo categoryId
    .value();

  if (products.length === 0) {
    return res
      .status(404)
      .json({ message: "No products found in this category" });
  }

  res.json(products);
});

server.use(router);

server.listen(3000, () => {
  console.log("JSON Server is running on http://localhost:3000");
});
