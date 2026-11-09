// Minimal zero-dependency Node app — a runnable target for Phase 4 dynamic analysis.
// It boots cleanly and serves "/", so a deep scan should report "booted and served".
const http = require("http");

const port = process.env.PORT || 3000;

http
  .createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<h1>runnable-node fixture</h1><p>Dynamic analysis target: boots cleanly.</p>");
  })
  .listen(port, "0.0.0.0", () => console.log(`listening on ${port}`));
