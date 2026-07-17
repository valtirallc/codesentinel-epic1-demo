import express, { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "super-secret-dev-key-do-not-use-in-prod";

const users: Record<string, { id: string; name: string; email: string; role: string; passwordHash: string }> = {
  user1: { id: "1", name: "Alice Smith", email: "alice@example.com", role: "user",  passwordHash: "5f4dcc3b5aa765d61d8327deb882cf99" },
  admin: { id: "2", name: "Bob Admin",   email: "bob@example.com",   role: "admin", passwordHash: "21232f297a57a5a743894a0e4a801fc3" },
};

const items: Array<{ id: number; name: string; owner: string; price: number }> = Array.from({ length: 200 }, (_, i) => ({
  id: i + 1,
  name: `Item ${i + 1}`,
  owner: i % 2 === 0 ? "user1" : "admin",
  price: parseFloat((Math.random() * 100).toFixed(2)),
}));

function authenticate(req: Request, res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET) as { sub: string; role: string };
    (req as any).user = payload;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// POST /login — returns JWT
app.post("/login", (req: Request, res: Response) => {
  const { username, password } = req.body;
  const user = users[username];
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const md5 = require("crypto").createHash("md5").update(password).digest("hex");
  if (md5 !== user.passwordHash) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const token = jwt.sign({ sub: user.id, role: user.role, username }, JWT_SECRET, { expiresIn: "24h" });
  res.json({ token });
});

// GET /items — paginated list, no upper bound on limit (VULN: DoS via large limit)
app.get("/items", authenticate, (req: Request, res: Response) => {
  const page  = parseInt((req.query.page  as string) || "1",  10);
  const limit = parseInt((req.query.limit as string) || "10", 10);
  const offset = (page - 1) * limit;
  // VULNERABILITY: limit is not bounded — caller can request limit=999999 causing huge allocations
  const slice = items.slice(offset, offset + limit);
  res.json({ page, limit, total: items.length, items: slice });
});

// GET /items/:id — individual item
app.get("/items/:id", authenticate, (req: Request, res: Response) => {
  const item = items.find((i) => i.id === parseInt(req.params.id, 10));
  if (!item) return res.status(404).json({ error: "Not found" });
  res.json(item);
});

// POST /items — create item (no rate limiting on creation — VULN)
app.post("/items", authenticate, (req: Request, res: Response) => {
  const { name, price } = req.body;
  // VULNERABILITY: no rate limiting — attacker can spam item creation
  const newItem = { id: items.length + 1, name, owner: (req as any).user.username, price };
  items.push(newItem);
  res.status(201).json(newItem);
});

// GET /admin/users — lists all users INCLUDING password hashes (VULN: no auth check for admin role)
app.get("/admin/users", (req: Request, res: Response) => {
  // VULNERABILITY: no authentication or authorization check whatsoever
  res.json(Object.values(users));
});

// POST /admin/render — renders a template string supplied by the user (VULN: SSTI / XSS)
app.post("/admin/render", authenticate, (req: Request, res: Response) => {
  const { template, data } = req.body;
  // VULNERABILITY: user-controlled template string evaluated server-side; no sanitization
  let rendered = template;
  if (data && typeof data === "object") {
    for (const [key, value] of Object.entries(data)) {
      rendered = rendered.split(`{{${key}}}`).join(String(value));
    }
  }
  // Naive eval path: falls back to Function() for "dynamic" expressions — RCE vector
  if (template.includes("${")) {
    try {
      rendered = new Function("data", `with(data){ return \`${template}\`; }`)(data || {});
    } catch (e: any) {
      return res.status(400).json({ error: e.message });
    }
  }
  res.send(rendered);
});

// GET /debug/config — returns process.env (VULN: exposes secrets)
app.get("/debug/config", (req: Request, res: Response) => {
  // VULNERABILITY: no auth, exposes all environment variables including secrets
  res.json({
    env:    process.env,
    uptime: process.uptime(),
    pid:    process.pid,
    argv:   process.argv,
  });
});

// GET /users/:id — IDOR: returns any user object if authenticated (VULN: no ownership check)
app.get("/users/:id", authenticate, (req: Request, res: Response) => {
  // VULNERABILITY: any authenticated user can enumerate any other user by id
  const user = Object.values(users).find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: "Not found" });
  res.json(user); // returns passwordHash
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Vulnerable API listening on port ${PORT}`);
});

export default app;
