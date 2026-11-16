// Test cases for ../javascript.yml. "ruleid:" marks a line that must match, "ok:" one that
// must not. Run: semgrep --test --config backend/rules backend/rules/tests
const express = require("express");
const { exec, execFile } = require("child_process");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const app = express();

// ---------------------------------------------------------------- SQL
app.post("/login", (req, res) => {
  const { username } = req.body;
  // ruleid: js-sql-built-from-strings
  const sql = `SELECT * FROM users WHERE username = '${username}'`;
  db.query(sql, () => {});
  // ruleid: js-sql-built-from-strings
  db.query("DELETE FROM users WHERE id = " + req.params.id);
  // ruleid: js-sql-built-from-strings
  pool.execute(`SELECT * FROM t WHERE id = ${req.query.id}`);
  // ok: js-sql-built-from-strings
  db.query("SELECT price FROM products WHERE id = ?", [req.query.id]);
  // ok: js-sql-built-from-strings
  db.query("SELECT 1 " + "FROM dual");
});

// ---------------------------------------------------------------- command injection
app.get("/export", (req, res) => {
  // ruleid: js-command-injection
  exec("zip -r /tmp/report.zip " + req.query.folder, () => {});
  const name = req.body.name;
  // ruleid: js-command-injection
  exec(`convert ${name} out.png`);
  // ok: js-command-injection
  execFile("zip", ["-r", "/tmp/r.zip", req.query.folder]);
  // ok: js-command-injection
  exec("ls -la");
  // ok: js-command-injection
  /a+/.exec(req.query.q);
});

// ---------------------------------------------------------------- XSS
app.get("/search", (req, res) => {
  const q = req.query.q;
  // ruleid: js-reflected-xss
  res.send(`<h1>Results for ${q}</h1>`);
});
app.get("/safe", (req, res) => {
  // ok: js-reflected-xss
  res.send(`<h1>Results for ${escapeHtml(req.query.q)}</h1>`);
  // ok: js-reflected-xss
  res.send("static page");
});

function render(el, html) {
  // ruleid: js-dom-xss-sink
  el.innerHTML = html;
  // ok: js-dom-xss-sink
  el.innerHTML = "<b>fixed</b>";
  // ok: js-dom-xss-sink
  el.textContent = html;
}

// ---------------------------------------------------------------- eval
function calc(expr) {
  // ruleid: js-code-eval
  return eval(expr);
}
// ok: js-code-eval
eval("1 + 1");
// ok: js-code-eval
setTimeout(() => calc("2"), 10);

// ---------------------------------------------------------------- files, redirects, SSRF
app.get("/file", (req, res) => {
  // ruleid: js-path-traversal
  res.sendFile(req.query.name);
  // ruleid: js-path-traversal
  fs.readFile(path.join("/data", req.params.file), () => {});
  // ok: js-path-traversal
  res.sendFile(path.join("/data", path.basename(req.query.name)));
});
app.get("/go", (req, res) => {
  // ruleid: js-open-redirect
  res.redirect(req.query.next);
  // ok: js-open-redirect
  res.redirect("/home");
});
app.post("/preview", async (req, res) => {
  // ruleid: js-ssrf
  const r = await fetch(req.body.url);
  // ok: js-ssrf
  const ok = await fetch("https://api.example.com/v1");
  res.json({ r, ok });
});
app.post("/mongo-login", async (req, res) => {
  // ruleid: js-nosql-injection
  const user = await User.findOne({ username: req.body.username, password: req.body.password });
  // ok: js-nosql-injection
  const user2 = await User.findOne({ username: String(req.body.username) });
  res.json({ user, user2 });
});

// ---------------------------------------------------------------- auth and secrets
function auth(req, res, next) {
  // ruleid: js-jwt-decode-without-verify
  req.user = jwt.decode(req.headers.authorization);
  // ok: js-jwt-decode-without-verify
  req.user = jwt.verify(req.headers.authorization, process.env.JWT_SECRET, { algorithms: ["HS256"] });
  next();
}
// ruleid: js-jwt-hardcoded-secret, js-hardcoded-credential
const JWT_SECRET = "supersecret123";
function issue(user) {
  // ruleid: js-jwt-hardcoded-secret
  jwt.sign({ id: user.id }, JWT_SECRET);
  // ruleid: js-jwt-hardcoded-secret
  jwt.sign({ id: user.id }, "another-secret");
  // ok: js-jwt-hardcoded-secret
  jwt.sign({ id: user.id }, process.env.JWT_SECRET);
}

// ruleid: js-hardcoded-db-password
const db = mysql.createConnection({ host: "localhost", user: "root", password: "admin123", database: "shop" });
// ok: js-hardcoded-db-password
const db2 = mysql.createConnection({ host: "localhost", password: process.env.DB_PASSWORD });

// ruleid: js-hardcoded-credential
const STRIPE_API_KEY = "sk_live_FAKE_EXAMPLE_KEY_0000";
// ok: js-hardcoded-credential
const DB_PASSWORD = "changeme";
// ok: js-hardcoded-credential
const API_KEY = process.env.API_KEY;

// ruleid: js-tls-verification-disabled
const agent = new https.Agent({ rejectUnauthorized: false });
// ruleid: js-tls-verification-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// ruleid: js-cors-any-origin
app.use(cors({ origin: "*" }));
// ok: js-cors-any-origin
app.use(cors({ origin: ["https://myapp.com"] }));

// ruleid: js-weak-random-token
const resetToken = Math.random().toString(36).slice(2);
// ok: js-weak-random-token
const jitter = Math.random() * 100;

function store(password) {
  // ruleid: js-weak-password-hash
  return crypto.createHash("md5").update(password).digest("hex");
}
// ok: js-weak-password-hash
const etag = crypto.createHash("sha256").update(body).digest("hex");

// ---------------------------------------------------------------- logic
app.post("/checkout", async (req, res) => {
  let total = 0;
  // ruleid: js-async-foreach
  req.body.items.forEach(async (item) => {
    total += (await getPrice(item.id)) * item.qty;
  });
  // ok: js-async-foreach
  for (const item of req.body.items) { total += await getPrice(item.id); }
  // ruleid: js-loose-equality-auth
  if (req.body.coupon == "FREE") total = 0;
  res.json({ charged: total });
});

function getPrice(id) {
  return new Promise((resolve) => {
    db.query("SELECT price FROM products WHERE id = ?", [id], (err, rows) => {
      // ruleid: js-unchecked-query-result
      resolve(rows[0].price);
    });
  });
}
function getPriceSafe(id) {
  return new Promise((resolve, reject) => {
    db.query("SELECT price FROM products WHERE id = ?", [id], (err, rows) => {
      if (err) return reject(err);
      // ok: js-unchecked-query-result
      resolve(rows[0].price);
    });
  });
}
