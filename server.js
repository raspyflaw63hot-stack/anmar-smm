
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");
const TelegramBot = require("node-telegram-bot-api");

const app = express();
const PORT = process.env.PORT || 3000;

const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
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

app.set("trust proxy", 1);
app.use(session({
  secret: SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: "auto",
    maxAge: 60 * 60 * 1000
  }
}));


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
    const normalizedEmail = String(email || "").trim().toLowerCase();

    if (
      !name || !normalizedEmail ||
      typeof password !== "string" ||
      password.length < 8 || password.length > 72
    ) {
      return res.status(400).json({
        message: "تحقق من البيانات وكلمة المرور"
      });
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [normalizedEmail]
    );

    if (existing.rowCount) {
      return res.status(409).json({
        message: "الحساب موجود مسبقاً"
      });
    }

    const hash = await bcrypt.hash(password, 12);
    const id = crypto.randomUUID();

    await pool.query(
      `INSERT INTO users (id, name, email, password_hash)
       VALUES ($1, $2, $3, $4)`,
      [id, String(name).trim(), normalizedEmail, hash]
    );

    await new Promise((resolve, reject) => {
      req.session.regenerate(err => err ? reject(err) : resolve());
    });

    req.session.userId = id;

    res.status(201).json({
      message: "تم إنشاء الحساب بنجاح"
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error.message);
    res.status(500).json({
      message: "حدث خطأ في إنشاء الحساب"
    });
  }
});

app.post("/api/login", limiter, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = req.body.password || "";

    const result = await pool.query(
      "SELECT id, password_hash FROM users WHERE email = $1",
      [email]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        message: "بيانات الدخول غير صحيحة"
      });
    }

    await new Promise((resolve, reject) => {
      req.session.regenerate(err => err ? reject(err) : resolve());
    });

    req.session.userId = user.id;

    res.json({ message: "تم تسجيل الدخول بنجاح" });
  } catch (error) {
    console.error("LOGIN ERROR:", error.message);
    res.status(500).json({
      message: "حدث خطأ في تسجيل الدخول"
    });
  }
});

app.get("/api/me", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT name, email FROM users WHERE id = $1",
      [req.session.userId || ""]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        message: "غير مسجل الدخول"
      });
    }

    res.json(result.rows[0]);
  } catch {
    res.status(500).json({
      message: "حدث خطأ في الخادم"
    });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "تم تسجيل الخروج" });
  });
});


// Create a new authenticated order
app.post("/api/orders", async (req, res) => {
  try {
    const userId = req.session.userId;

    if (!userId) {
      return res.status(401).json({
        message: "سجل الدخول أولاً"
      });
    }

    const { platform, service, link, details = "" } = req.body;

    const platforms = ["TikTok", "Instagram", "Telegram"];
    const services = [
      "إدارة حساب",
      "صناعة محتوى",
      "حملة إعلانية"
    ];

    let parsedLink;
    try {
      parsedLink = new URL(link);
    } catch {
      return res.status(400).json({
        message: "الرابط غير صالح"
      });
    }

    if (
      !platforms.includes(platform) ||
      !services.includes(service) ||
      !["http:", "https:"].includes(parsedLink.protocol) ||
      String(details).length > 1000
    ) {
      return res.status(400).json({
        message: "تحقق من بيانات الطلب"
      });
    }

    const result = await pool.query(
      `INSERT INTO orders
       (user_id, platform, service, link, details)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, platform, service, status, created_at`,
      [userId, platform, service, parsedLink.href, String(details)]
    );

    res.status(201).json({
      message: "تم حفظ الطلب بنجاح",
      order: result.rows[0]
    });
  } catch (error) {
    console.error("ORDER CREATE ERROR:", error.message);
    res.status(500).json({
      message: "تعذر حفظ الطلب"
    });
  }
});

// Get orders belonging to the logged-in user
app.get("/api/orders", async (req, res) => {
  try {
    const userId = req.session.userId;

    if (!userId) {
      return res.status(401).json({
        message: "سجل الدخول أولاً"
      });
    }

    const result = await pool.query(
      `SELECT id, platform, service, status, created_at
       FROM orders
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [userId]
    );

    res.json({ orders: result.rows });
  } catch (error) {
    console.error("ORDER LIST ERROR:", error.message);
    res.status(500).json({
      message: "تعذر تحميل الطلبات"
    });
  }
});

async function startServer() {
  try {
    await pool.query("SELECT 1");

await pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )
`);



    await pool.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id BIGSERIAL PRIMARY KEY,
        user_id TEXT NOT NULL,
        platform TEXT NOT NULL,
        service TEXT NOT NULL,
        link TEXT NOT NULL,
        details TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    console.log("ORDERS TABLE READY");
    console.log("POSTGRESQL CONNECTED");

    if (process.env.TELEGRAM_BOT_TOKEN) {
      const bot = new TelegramBot(
        process.env.TELEGRAM_BOT_TOKEN,
        { polling: true }
      );

      bot.onText(/\/start/, (msg) => {
        bot.sendMessage(
          msg.chat.id,
          "👋 أهلاً بك في ANMAR SMM\n\n📱 خدمات إدارة وتسويق القنوات\n\nأرسل طلبك أو استفسارك وسنتواصل معك."
        );
      });

      bot.on("polling_error", (error) => {
        console.error("TELEGRAM ERROR:", error.message);
      });

      console.log("TELEGRAM BOT STARTED");
    } else {
      console.log("TELEGRAM TOKEN MISSING");
    }

    app.listen(PORT, "0.0.0.0", () => {
      console.log("ANMAR SMM SERVER RUNNING");
    });
  } catch (error) {
    console.error("DATABASE CONNECTION FAILED:", error.message);
    process.exit(1);
  }
}

startServer();

