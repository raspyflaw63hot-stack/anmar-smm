
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const SECRET = crypto.randomBytes(32).toString("hex");
const DB = path.join(__dirname, "users.json");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(session({
  secret: SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: false,
    maxAge: 60 * 60 * 1000
  }
}));

function readUsers() {
  try {
    return JSON.parse(fs.readFileSync(DB, "utf8"));
  } catch {
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync(DB, JSON.stringify(users, null, 2));
}

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

app.use(express.static(__dirname));

app.post("/api/register", limiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password ||
        password.length < 8 || password.length > 72) {
      return res.status(400).json({
        message: "تحقق من البيانات وكلمة المرور"
      });
    }

    const users = readUsers();
    const normalizedEmail = email.trim().toLowerCase();

    if (users.some(u => u.email === normalizedEmail)) {
      return res.status(409).json({
        message: "الحساب موجود مسبقاً"
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const user = {
      id: crypto.randomUUID(),
      name: name.trim(),
      email: normalizedEmail,
      password: hash
    };

    users.push(user);
    saveUsers(users);

    req.session.userId = user.id;

    res.json({ message: "تم إنشاء الحساب بنجاح" });

  } catch (error) {
    res.status(500).json({ message: "حدث خطأ في الخادم" });
  }
});

app.post("/api/login", limiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const users = readUsers();

    const user = users.find(
      u => u.email === String(email || "").trim().toLowerCase()
    );

    if (!user || !(await bcrypt.compare(password || "", user.password))) {
      return res.status(401).json({
        message: "بيانات الدخول غير صحيحة"
      });
    }

    req.session.userId = user.id;

    res.json({ message: "تم تسجيل الدخول بنجاح" });

  } catch {
    res.status(500).json({ message: "حدث خطأ في الخادم" });
  }
});

app.get("/api/me", (req, res) => {
  const user = readUsers().find(
    u => u.id === req.session.userId
  );

  if (!user) {
    return res.status(401).json({
      message: "غير مسجل الدخول"
    });
  }

  res.json({
    name: user.name,
    email: user.email
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "تم تسجيل الخروج" });
  });
});

async function startServer() {
  try {
    await pool.query("SELECT 1");
    console.log("POSTGRESQL CONNECTED");

    app.listen(PORT, "0.0.0.0", () => {
      console.log("ANMAR SMM SERVER RUNNING");
    });
  } catch (error) {
    console.error("DATABASE CONNECTION FAILED:", error.message);
    process.exit(1);
  }
}

startServer();

