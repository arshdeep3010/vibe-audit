// Tiny Express API — intentionally buggy sample for testing VibeAudit.
const express = require("express");
const mysql = require("mysql");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors({ origin: "*" })); // open CORS to everyone

// Hardcoded credentials committed straight into source.
const STRIPE_SECRET = "sk-live-abcd1234efgh5678ijkl9012mnop3456";
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "SuperSecret123!",
  database: "app",
});

// SQL injection: user input concatenated directly into the query.
app.get("/users", (req, res) => {
  const q = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  db.query(q, (err, rows) => {
    res.json(rows); // err ignored; rows may be undefined on error
  });
});

// Remote code execution: eval of attacker-controlled input.
app.post("/calc", (req, res) => {
  const result = eval(req.body.expr);
  res.send("" + result);
});

// Missing await: password check resolves to a Promise (always truthy).
async function getUser(id) {
  return db.promise().query("SELECT * FROM users WHERE id = " + id);
}
app.post("/login", async (req, res) => {
  const user = getUser(req.body.id); // forgot to await
  if (user.password === req.body.password) {
    res.json({ token: STRIPE_SECRET });
  } else {
    res.status(401).send("nope");
  }
});

// Leaks internal errors (and stack traces) to the client.
app.get("/crash", (req, res) => {
  const data = JSON.parse(req.query.payload);
  res.json(data.deeply.nested.value);
});

app.listen(3000, () => console.log("up on 3000"));
