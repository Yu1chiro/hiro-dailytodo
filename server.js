require("dotenv").config();
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");

const {
  PIN,
  JWT_SECRET,
  DATABASE_URL,
  PORT = 3000,
  APP_TZ = "Asia/Makassar",
  NODE_ENV,
} = process.env;

if (!PIN || !JWT_SECRET || !DATABASE_URL) {
  console.error("ENV wajib: PIN, JWT_SECRET, DATABASE_URL");
  process.exit(1);
}

const app = express();
app.set("trust proxy", 1);
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ---- path aman: file halaman TIDAK disajikan lewat express.static ----
const PUBLIC_DIR = path.join(__dirname, "public");
const page = (name) => path.join(PUBLIC_DIR, name);

app.disable("x-powered-by");
app.use((req, res, next) => {
  res.set({
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
  });
  next();
});
app.use(express.json({ limit: "50kb" }));
app.use(cookieParser());

// ---- helpers tanggal ----
const todayStr = () =>
  new Date().toLocaleDateString("en-CA", { timeZone: APP_TZ });
const addDays = (s, n) => {
  const d = new Date(s + "T00:00:00Z");
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
};
const monday = (s) =>
  addDays(s, -((new Date(s + "T00:00:00Z").getUTCDay() + 6) % 7));
const monthShift = (s, n) => {
  let [y, m] = s.split("-").map(Number);
  m += n;
  while (m < 1) {
    m += 12;
    y--;
  }
  while (m > 12) {
    m -= 12;
    y++;
  }
  return `${y}-${String(m).padStart(2, "0")}-01`;
};

// Validasi Tanggal Tanpa Regex
const isValidDate = (str) => {
  if (typeof str !== "string" || str.length !== 10) return false;
  const parts = str.split("-");
  if (parts.length !== 3) return false;
  const y = Number(parts[0]);
  const m = Number(parts[1]);
  const d = Number(parts[2]);
  return !isNaN(y) && !isNaN(m) && !isNaN(d);
};

// ---- auth (PIN dari .env + JWT di cookie httpOnly) ----
const sha = (s) => crypto.createHash("sha256").update(String(s)).digest();
const pinOk = (p) => crypto.timingSafeEqual(sha(p), sha(PIN));
const attempts = new Map();
const limited = (ip) => {
  const now = Date.now();
  const a = (attempts.get(ip) || []).filter((t) => now - t < 60000);
  attempts.set(ip, a);
  return a.length >= 5;
};
const verify = (req) => {
  try {
    return jwt.verify(req.cookies.token, JWT_SECRET);
  } catch {
    return null;
  }
};
const pageAuth = (req, res, next) =>
  verify(req) ? next() : res.status(401).type("html").send(LOGIN_HTML);
const apiAuth = (req, res, next) =>
  verify(req)
    ? next()
    : res.status(401).json({ error: "Sesi berakhir, masukkan PIN lagi" });
const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    console.error(e);
    res.status(500).json({ error: "Kesalahan server" });
  });

app.post("/api/login", (req, res) => {
  if (limited(req.ip))
    return res
      .status(429)
      .json({ error: "Terlalu banyak percobaan. Coba lagi 1 menit." });
  attempts.get(req.ip).push(Date.now());
  if (!req.body || !pinOk(req.body.pin ?? ""))
    return res.status(401).json({ error: "PIN salah" });
  attempts.delete(req.ip);
  const token = jwt.sign({ sub: "owner" }, JWT_SECRET, { expiresIn: "7d" });
  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "strict",
    secure: NODE_ENV === "production",
    maxAge: 7 * 864e5,
  });
  res.json({ ok: true });
});
app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

// ---- halaman (semua diproteksi) ----
app.get("/", pageAuth, (req, res) => res.sendFile(page("index.html")));
app.get("/calendar", pageAuth, (req, res) =>
  res.sendFile(page("calendar.html")),
);
app.get("/statistic", pageAuth, (req, res) =>
  res.sendFile(page("statistic.html")),
);

// ---- CRUD tugas ----
const COLS = `id,title,description,category,priority,status,to_char(due_date,'YYYY-MM-DD') AS due_date,completed_at,estimate_min,actual_min,created_at`;
const PRI = ["low", "medium", "high"];
const num = (v) =>
  v === undefined || v === null || v === "" ? null : parseInt(v, 10);

function clean(b = {}) {
  const title = String(b.title || "").trim();
  if (!title || title.length > 200)
    return { error: "Judul wajib diisi (maks 200 karakter)" };
  
  const priority = b.priority || "medium";
  if (!PRI.includes(priority)) return { error: "Prioritas tidak valid" };
  
  if (!isValidDate(b.due_date || "")) return { error: "Tanggal tidak valid" };
  
  const estimate_min = num(b.estimate_min);
  const actual_min = num(b.actual_min);
  
  for (const v of [estimate_min, actual_min]) {
    if (v !== null && (Number.isNaN(v) || v < 0 || v > 1440))
      return { error: "Durasi harus 0-1440 menit" };
  }
  const category =
    String(b.category || "Umum")
      .trim()
      .slice(0, 40) || "Umum";
  const description = String(b.description || "")
    .trim()
    .slice(0, 1000);
  return {
    v: {
      title,
      description,
      category,
      priority,
      due_date: b.due_date,
      estimate_min,
      actual_min,
    },
  };
}

app.get(
  "/api/tasks",
  apiAuth,
  wrap(async (req, res) => {
    const q = req.query,
      w = [],
      p = [];
    const add = (sql, v) => {
      p.push(v);
      w.push(sql.split("?").join("$" + p.length));
    };
    if (isValidDate(q.from || "")) add("due_date >= ?::date", q.from);
    if (isValidDate(q.to || "")) add("due_date <= ?::date", q.to);
    if (isValidDate(q.before || "")) add("due_date < ?::date", q.before);
    if (["todo", "done"].includes(q.status)) add("status = ?", q.status);
    if (PRI.includes(q.priority)) add("priority = ?", q.priority);
    if (q.category) add("category = ?", String(q.category).slice(0, 40));
    
    if (q.q) {
      // Escape karakter khusus pencarian tanpa Regex
      const safeQuery = String(q.q)
        .slice(0, 100)
        .split("\\").join("\\\\")
        .split("%").join("\\%")
        .split("_").join("\\_");
      
      add(
        "(title ILIKE ? OR description ILIKE ?)",
        "%" + safeQuery + "%"
      );
    }
    const sql = `SELECT ${COLS} FROM tasks ${w.length ? "WHERE " + w.join(" AND ") : ""}
    ORDER BY due_date ASC, (status='done') ASC, CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, id LIMIT 1000`;
    res.json((await pool.query(sql, p)).rows);
  }),
);

app.get(
  "/api/categories",
  apiAuth,
  wrap(async (req, res) => {
    res.json(
      (
        await pool.query("SELECT DISTINCT category FROM tasks ORDER BY 1")
      ).rows.map((r) => r.category),
    );
  }),
);

app.post(
  "/api/tasks",
  apiAuth,
  wrap(async (req, res) => {
    const { v, error } = clean(req.body);
    if (error) return res.status(400).json({ error });
    const r = await pool.query(
      `INSERT INTO tasks (title,description,category,priority,due_date,estimate_min,actual_min)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING ${COLS}`,
      [
        v.title,
        v.description,
        v.category,
        v.priority,
        v.due_date,
        v.estimate_min,
        v.actual_min,
      ],
    );
    res.status(201).json(r.rows[0]);
  }),
);

app.put(
  "/api/tasks/:id",
  apiAuth,
  wrap(async (req, res) => {
    const id = Number(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "ID Tugas Tidak Valid" });

    const { v, error } = clean(req.body);
    if (error) return res.status(400).json({ error });
    
    const r = await pool.query(
      `UPDATE tasks SET title=$1,description=$2,category=$3,priority=$4,due_date=$5,estimate_min=$6,actual_min=$7,updated_at=now()
     WHERE id=$8 RETURNING ${COLS}`,
      [
        v.title,
        v.description,
        v.category,
        v.priority,
        v.due_date,
        v.estimate_min,
        v.actual_min,
        id,
      ],
    );
    if (!r.rowCount)
      return res.status(404).json({ error: "Tugas tidak ditemukan" });
    res.json(r.rows[0]);
  }),
);

app.patch(
  "/api/tasks/:id/toggle",
  apiAuth,
  wrap(async (req, res) => {
    const id = Number(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "ID Tugas Tidak Valid" });

    const r = await pool.query(
      `UPDATE tasks SET
       status = CASE WHEN status='done' THEN 'todo' ELSE 'done' END,
       completed_at = CASE WHEN status='done' THEN NULL ELSE now() END,
       updated_at = now()
     WHERE id=$1 RETURNING ${COLS}`,
      [id],
    );
    if (!r.rowCount)
      return res.status(404).json({ error: "Tugas tidak ditemukan" });
    res.json(r.rows[0]);
  }),
);

app.delete(
  "/api/tasks/:id",
  apiAuth,
  wrap(async (req, res) => {
    const id = Number(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "ID Tugas Tidak Valid" });

    const r = await pool.query("DELETE FROM tasks WHERE id=$1", [id]);
    if (!r.rowCount)
      return res.status(404).json({ error: "Tugas tidak ditemukan" });
    res.json({ ok: true });
  }),
);

// ---- streak & statistik ----
async function getStreak() {
  const today = todayStr();
  const { rows } = await pool.query(
    `SELECT DISTINCT to_char((completed_at AT TIME ZONE $1)::date,'YYYY-MM-DD') d
     FROM tasks WHERE status='done' AND completed_at IS NOT NULL ORDER BY d`,
    [APP_TZ],
  );
  const days = rows.map((r) => r.d),
    set = new Set(days);
  let cur = 0,
    c = set.has(today) ? today : addDays(today, -1);
  while (set.has(c)) {
    cur++;
    c = addDays(c, -1);
  }
  let best = 0,
    run = 0,
    prev = null;
  for (const x of days) {
    run = prev && addDays(prev, 1) === x ? run + 1 : 1;
    best = Math.max(best, run);
    prev = x;
  }
  return { current: cur, longest: best, todayDone: set.has(today) };
}
app.get(
  "/api/streak",
  apiAuth,
  wrap(async (req, res) => res.json(await getStreak())),
);

app.get(
  "/api/stats",
  apiAuth,
  wrap(async (req, res) => {
    const tz = APP_TZ,
      today = todayStr();
    const dStart = addDays(today, -29),
      wStart = addDays(monday(today), -77),
      mStart = monthShift(today.slice(0, 7) + "-01", -11),
      r90 = addDays(today, -89);
    const agg = `count(*)::int total, count(*) FILTER (WHERE status='done')::int done`;
    const late = `count(*) FILTER (WHERE status='done' AND (completed_at AT TIME ZONE $3)::date > due_date)::int late`;
    const [d, w, m, cat, pri, wd, tot, streak] = await Promise.all([
      pool.query(
        `SELECT to_char(due_date,'YYYY-MM-DD') k, ${agg} FROM tasks WHERE due_date BETWEEN $1::date AND $2::date GROUP BY 1`,
        [dStart, today],
      ),
      pool.query(
        `SELECT to_char(date_trunc('week',due_date),'YYYY-MM-DD') k, ${agg} FROM tasks WHERE due_date BETWEEN $1::date AND $2::date GROUP BY 1`,
        [wStart, today],
      ),
      pool.query(
        `SELECT to_char(due_date,'YYYY-MM') k, ${agg} FROM tasks WHERE due_date BETWEEN $1::date AND $2::date GROUP BY 1`,
        [mStart, today],
      ),
      pool.query(
        `SELECT category k, ${agg}, ${late} FROM tasks WHERE due_date BETWEEN $1::date AND $2::date GROUP BY 1`,
        [r90, today, tz],
      ),
      pool.query(
        `SELECT priority k, ${agg}, ${late} FROM tasks WHERE due_date BETWEEN $1::date AND $2::date GROUP BY 1`,
        [r90, today, tz],
      ),
      pool.query(
        `SELECT EXTRACT(ISODOW FROM due_date)::int k, ${agg} FROM tasks WHERE due_date BETWEEN $1::date AND $2::date GROUP BY 1 ORDER BY 1`,
        [r90, today],
      ),
      pool.query(
        `SELECT count(*)::int total,
        count(*) FILTER (WHERE status='done')::int done,
        count(*) FILTER (WHERE status='done' AND (completed_at AT TIME ZONE $1)::date <= due_date)::int on_time,
        count(*) FILTER (WHERE status='todo' AND due_date < $2::date)::int overdue,
        COALESCE(sum(actual_min) FILTER (WHERE status='done' AND estimate_min>0 AND actual_min>0),0)::int act,
        COALESCE(sum(estimate_min) FILTER (WHERE status='done' AND estimate_min>0 AND actual_min>0),0)::int est
       FROM tasks WHERE due_date <= $2::date`,
        [tz, today],
      ),
      getStreak(),
    ]);
    const fill = (rows, keys) => {
      const mp = new Map(rows.map((r) => [r.k, r]));
      return keys.map((k) => mp.get(k) || { k, total: 0, done: 0 });
    };
    const dKeys = Array.from({ length: 30 }, (_, i) => addDays(dStart, i));
    const wKeys = Array.from({ length: 12 }, (_, i) => addDays(wStart, i * 7));
    const mKeys = Array.from({ length: 12 }, (_, i) =>
      monthShift(mStart, i).slice(0, 7),
    );
    res.json({
      today,
      daily: fill(d.rows, dKeys),
      weekly: fill(w.rows, wKeys),
      monthly: fill(m.rows, mKeys),
      category: cat.rows,
      priority: pri.rows,
      weekday: wd.rows,
      totals: tot.rows[0],
      streak,
    });
  }),
);

app.use("/api", (req, res) =>
  res.status(404).json({ error: "Endpoint tidak ditemukan" }),
);
app.use((req, res) => res.redirect("/"));

app.listen(PORT, () =>
  console.log(`Taman Harian berjalan di http://localhost:${PORT}`),
);

// ---- halaman PIN ----
const LOGIN_HTML = `<!DOCTYPE html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Masuk - Taman Harian</title>
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;700&family=Zen+Maru+Gothic:wght@700&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<style>body{font-family:Nunito,sans-serif;color:#23443a;min-height:100vh;background:radial-gradient(circle at 88% 6%,rgba(250,224,148,.6),transparent 32%),radial-gradient(ellipse at 15% 108%,rgba(70,140,90,.32),transparent 52%),linear-gradient(165deg,#c7e7ee 0%,#e5f3e3 45%,#b8dcac 100%)}
h1{font-family:'Zen Maru Gothic',sans-serif}</style></head>
<body class="grid place-items-center p-5">
<div id="toasts" class="fixed top-3 inset-x-0 z-50 flex flex-col items-center gap-2 px-4 pointer-events-none"></div>
<form id="f" class="w-full max-w-sm rounded-[32px] p-7 shadow-xl" style="background:rgba(255,255,255,.7);backdrop-filter:blur(14px)">
<h1 class="text-3xl">おかえり ひろ👋</h1>
<p class="mt-1 text-sm opacity-75">頑張ってくれてありがとうね！</p>
<p class="mt-1 text-sm opacity-75">今日、ぜひ頑張りましょう！</p>
<label for="pin" class="block mt-6 text-sm font-bold">ピン入れてください！</label>
<input id="pin" type="password" inputmode="numeric" autocomplete="current-password" autofocus class="mt-1 w-full rounded-2xl border border-emerald-800/25 bg-white/80 px-4 py-3 text-lg tracking-[.4em] outline-none focus:ring-4 focus:ring-emerald-300/60">
<button class="mt-5 w-full rounded-full bg-emerald-700 py-3 font-bold text-white hover:bg-emerald-900 transition">ロギン</button>
</form>
<script>
function toast(m){var e=document.createElement('div');e.className='pointer-events-auto rounded-2xl bg-rose-500 text-white px-5 py-3 shadow-lg font-bold';e.textContent=m;document.getElementById('toasts').appendChild(e);setTimeout(function(){e.remove()},3200)}
document.getElementById('f').addEventListener('submit',function(ev){ev.preventDefault();var v=document.getElementById('pin').value.trim();
if(!v){toast('PIN wajib diisi');return}
fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin:v})})
.then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})})
.then(function(x){if(x.ok){location.reload()}else{toast(x.j.error||'Gagal masuk');document.getElementById('pin').value=''}})
.catch(function(){toast('Tidak bisa terhubung ke server')})});
</script></body></html>`;