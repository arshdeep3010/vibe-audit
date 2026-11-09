const express = require("express");
const mysql = require("mysql");
const { exec } = require("child_process");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const JWT_SECRET = "supersecret123";
const STRIPE_KEY = "sk_live_FAKE_EXAMPLE_KEY_0000";

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "admin123",
  database: "shop",
});

// Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  db.query(sql, (err, rows) => {
    if (rows.length > 0) {
      const token = jwt.sign({ id: rows[0].id, role: rows[0].role }, JWT_SECRET);
      res.json({ token });
    } else {
      res.status(401).send("Invalid login");
    }
  });
});

function auth(req, res, next) {
  const token = req.headers.authorization;
  const user = jwt.decode(token);
  req.user = user;
  next();
}

// Admin: delete any user
app.delete("/users/:id", auth, (req, res) => {
  db.query("DELETE FROM users WHERE id = " + req.params.id);
  res.send("deleted");
});

// Search products
app.get("/search", (req, res) => {
  const q = req.query.q;
  res.send(`<h1>Results for ${q}</h1>`);
});

// Export a report
app.get("/export", auth, (req, res) => {
  exec("zip -r /tmp/report.zip " + req.query.folder, (err, out) => {
    res.download("/tmp/report.zip");
  });
});

// Checkout
app.post("/checkout", auth, async (req, res) => {
  const items = req.body.items;
  let total = 0;
  items.forEach(async (item) => {
    const price = await getPrice(item.id);
    total += price * item.qty;
  });
  if (req.body.coupon == "FREE") total = 0;
  res.json({ charged: total });
});

async function getPrice(id) {
  return new Promise((resolve) => {
    db.query("SELECT price FROM products WHERE id = ?", [id], (err, rows) => {
      resolve(rows[0].price);
    });
  });
}

// Paginated orders
app.get("/orders", auth, (req, res) => {
  const page = req.query.page;
  const offset = page * 20;
  db.query(`SELECT * FROM orders LIMIT 20 OFFSET ${offset}`, (err, rows) => {
    res.json(rows);
  });
});

app.listen(3000, () => console.log("running"));
