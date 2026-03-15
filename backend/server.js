const express  = require("express");
const cors     = require("cors");
const { Pool } = require("pg");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");

const app  = express();
const PORT = process.env.PORT || 3000;

// ── JWT Secret — MUST be set in environment variables ──────────
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("❌ JWT_SECRET no configurado o muy corto. Mínimo 32 caracteres.");
  process.exit(1);
}

// ── CORS ───────────────────────────────────────────────────────
app.use(cors({
  origin: "*",
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"]
}));
app.options("*", cors());
app.use(express.json({ limit: "20mb" }));

// ── FORCE HTTPS in production ──────────────────────────────────
if (process.env.NODE_ENV === "production") {
  app.use((req, res, next) => {
    if (req.headers["x-forwarded-proto"] !== "https") {
      return res.redirect(301, "https://" + req.headers.host + req.url);
    }
    next();
  });
}

// ══════════════════════════════════════════════════════════════
//  RATE LIMITING — sin dependencias externas
// ══════════════════════════════════════════════════════════════
const rateLimitStore = new Map();

function rateLimit({ windowMs, max, message }) {
  return (req, res, next) => {
    const key  = req.ip + ":" + req.path;
    const now  = Date.now();
    const data = rateLimitStore.get(key) || { count: 0, start: now };

    // Reset window if expired
    if (now - data.start > windowMs) {
      data.count = 0;
      data.start = now;
    }

    data.count++;
    rateLimitStore.set(key, data);

    // Cleanup old entries every 10 min
    if (rateLimitStore.size > 10000) {
      for (const [k, v] of rateLimitStore) {
        if (now - v.start > windowMs) rateLimitStore.delete(k);
      }
    }

    if (data.count > max) {
      const retryAfter = Math.ceil((data.start + windowMs - now) / 1000);
      res.setHeader("Retry-After", retryAfter);
      return res.status(429).json({ error: message || "Demasiadas solicitudes. Intenta más tarde." });
    }
    next();
  };
}

// Specific limiters
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 10,                    // 10 attempts per 15 min per IP
  message: "Demasiados intentos de login. Espera 15 minutos."
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,        // 1 minute
  max: 60,                    // 60 requests per minute
  message: "Demasiadas solicitudes. Intenta más tarde."
});

const orderLimiter = rateLimit({
  windowMs: 60 * 1000,        // 1 minute
  max: 5,                     // max 5 orders per minute per IP
  message: "Demasiados pedidos. Espera un momento."
});

// ══════════════════════════════════════════════════════════════
//  INPUT VALIDATION HELPERS
// ══════════════════════════════════════════════════════════════
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sanitizeStr(val, maxLen = 200) {
  if (typeof val !== "string") return "";
  return val.trim().slice(0, maxLen);
}

function validatePositiveNum(val) {
  const n = parseFloat(val);
  return !isNaN(n) && n >= 0;
}

function validatePedidoItems(items) {
  if (!Array.isArray(items) || items.length === 0 || items.length > 50) return false;
  return items.every(i =>
    typeof i.nombre === "string" && i.nombre.trim() &&
    validatePositiveNum(i.precio) &&
    Number.isInteger(Number(i.cantidad)) && Number(i.cantidad) >= 1 && Number(i.cantidad) <= 999
  );
}

// ── POSTGRESQL ─────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

async function connectDB() {
  try {
    const client = await pool.connect();
    console.log("✅ Conectado a PostgreSQL");
    client.release();
  } catch (err) {
    console.error("❌ Error de conexión:", err.message);
    process.exit(1);
  }
}

// ── INIT DATABASE ──────────────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    // Migration: add stock column if missing
    await client.query(
      "ALTER TABLE productos ADD COLUMN IF NOT EXISTS stock INT NOT NULL DEFAULT 0"
    ).catch(() => {});

    await client.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id             SERIAL PRIMARY KEY,
        nombre         VARCHAR(100) NOT NULL,
        email          VARCHAR(200) NOT NULL UNIQUE,
        password_hash  VARCHAR(255) NOT NULL,
        activo         BOOLEAN NOT NULL DEFAULT true,
        fecha_creacion TIMESTAMP NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS productos (
        id             SERIAL PRIMARY KEY,
        nombre         VARCHAR(200) NOT NULL,
        descripcion    TEXT NOT NULL,
        precio         DECIMAL(10,2) NOT NULL CHECK (precio >= 0),
        imagen         TEXT NULL,
        stock          INT NOT NULL DEFAULT 0 CHECK (stock >= 0),
        estado         VARCHAR(20) NOT NULL DEFAULT 'activo'
                       CHECK (estado IN ('activo','inactivo')),
        fecha_creacion TIMESTAMP NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS pedidos (
        id             SERIAL PRIMARY KEY,
        nombre         VARCHAR(100) NOT NULL,
        apellido       VARCHAR(100) NOT NULL,
        telefono       VARCHAR(30)  NOT NULL,
        ubicacion      VARCHAR(500) NOT NULL,
        total          DECIMAL(10,2) NOT NULL CHECK (total >= 0),
        metodo_pago    VARCHAR(50)  NOT NULL,
        estado         VARCHAR(20)  NOT NULL DEFAULT 'pendiente'
                       CHECK (estado IN ('pendiente','confirmado','entregado','cancelado')),
        fecha_creacion TIMESTAMP NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS detalle_pedido (
        id              SERIAL PRIMARY KEY,
        pedido_id       INT NOT NULL REFERENCES pedidos(id) ON DELETE CASCADE,
        producto_id     INT NULL REFERENCES productos(id) ON DELETE SET NULL,
        nombre_producto VARCHAR(200) NOT NULL,
        precio          DECIMAL(10,2) NOT NULL CHECK (precio >= 0),
        cantidad        INT NOT NULL DEFAULT 1 CHECK (cantidad > 0)
      );
    `);

    // Admin inicial
    const adminCheck = await client.query(
      "SELECT id FROM usuarios WHERE email = 'admin@dulceinspiracion.com'"
    );
    if (adminCheck.rows.length === 0) {
      const hash = await bcrypt.hash("Admin123!", 12); // rounds=12 más seguro
      await client.query(
        "INSERT INTO usuarios (nombre, email, password_hash) VALUES ($1,$2,$3)",
        ["Administrador", "admin@dulceinspiracion.com", hash]
      );
      console.log("✅ Admin creado → admin@dulceinspiracion.com / Admin123!");
    }

    // Productos de ejemplo
    const prodCheck = await client.query("SELECT COUNT(*) FROM productos");
    if (parseInt(prodCheck.rows[0].count) === 0) {
      await client.query(`
        INSERT INTO productos (nombre, descripcion, precio, stock, estado) VALUES
        ('Caja de Bombones Premium','Deliciosos bombones de chocolate belga con relleno de trufa y caramelo. Presentación elegante en caja de 12 unidades.',850,20,'activo'),
        ('Paletas Artesanales x6','Paletas de frutas tropicales hechas a mano: mango, tamarindo, parcha y más.',320,30,'activo'),
        ('Dulces de Leche Surtidos','Variedad de dulces de leche tradicionales: con coco, con nuez y clásicos. Bolsa de 500g.',450,25,'activo'),
        ('Torta de Chocolate Premium','Torta húmeda de chocolate con ganache y decoración artesanal. Para 8-10 personas.',1200,10,'activo'),
        ('Macarons Franceses x12','Macarons con rellenos de vainilla, frambuesa y pistache.',750,15,'activo'),
        ('Kit Candy Bar Fiesta','Todo para tu candy bar: gomitas, masmelos, chocolatinas y más. Para 30 personas.',2200,8,'activo')
      `);
      console.log("✅ Productos de ejemplo insertados");
    }

    console.log("✅ Base de datos lista");
  } finally {
    client.release();
  }
}

// ── AUTH MIDDLEWARE ─────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token requerido" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) {
    const msg = e.name === "TokenExpiredError"
      ? "La sesión expiró. Inicia sesión de nuevo."
      : "Token inválido.";
    res.status(401).json({ error: msg });
  }
}

// ══════════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════════

// ── Health check ───────────────────────────────────────────────
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ── Login — with rate limiting ─────────────────────────────────
app.post("/api/login", loginLimiter, async (req, res) => {
  const email    = sanitizeStr(req.body.email, 200).toLowerCase();
  const password = sanitizeStr(req.body.password, 100);

  if (!email || !password)
    return res.status(400).json({ error: "Email y contraseña requeridos" });
  if (!validateEmail(email))
    return res.status(400).json({ error: "Email inválido" });

  try {
    const result = await pool.query(
      "SELECT * FROM usuarios WHERE email=$1 AND activo=true", [email]
    );
    const user = result.rows[0];
    // Always compare hash even if user not found (prevent timing attacks)
    const fakeHash = "$2a$12$invalidhashtopreventtimingattacks00000000000000000000000";
    const hash = user ? user.password_hash : fakeHash;
    const ok   = await bcrypt.compare(password, hash);

    if (!user || !ok)
      return res.status(401).json({ error: "Credenciales incorrectas" });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "8h" }
    );
    res.json({ token, nombre: user.nombre, email: user.email });
  } catch (err) {
    res.status(500).json({ error: "Error del servidor" });
  }
});

// ── Usuarios Admin ─────────────────────────────────────────────
app.get("/api/admin/usuarios", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, nombre, email, activo, fecha_creacion FROM usuarios ORDER BY fecha_creacion ASC"
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: "Error del servidor" }); }
});

app.post("/api/admin/usuarios", authMiddleware, async (req, res) => {
  const nombre   = sanitizeStr(req.body.nombre, 100);
  const email    = sanitizeStr(req.body.email, 200).toLowerCase();
  const password = sanitizeStr(req.body.password, 100);

  if (!nombre || !email || !password)
    return res.status(400).json({ error: "Todos los campos son requeridos" });
  if (!validateEmail(email))
    return res.status(400).json({ error: "Email inválido" });
  if (password.length < 8)
    return res.status(400).json({ error: "La contraseña debe tener al menos 8 caracteres" });
  if (password.length > 72)
    return res.status(400).json({ error: "Contraseña demasiado larga" });

  try {
    const hash   = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO usuarios (nombre, email, password_hash) VALUES ($1,$2,$3) RETURNING id, nombre, email",
      [nombre, email, hash]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") return res.status(400).json({ error: "Ese email ya está registrado" });
    res.status(500).json({ error: "Error del servidor" });
  }
});

app.delete("/api/admin/usuarios/:id", authMiddleware, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: "ID inválido" });
  if (id === req.user.id)
    return res.status(400).json({ error: "No puedes eliminarte a ti mismo" });
  try {
    await pool.query("DELETE FROM usuarios WHERE id=$1", [id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: "Error del servidor" }); }
});

// ── Productos públicos ──────────────────────────────────────────
app.get("/api/productos", apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, nombre, descripcion, precio, imagen, stock, estado, fecha_creacion FROM productos WHERE estado='activo' ORDER BY fecha_creacion DESC"
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: "Error del servidor" }); }
});

// ── Productos Admin ─────────────────────────────────────────────
app.get("/api/admin/productos", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM productos ORDER BY fecha_creacion DESC"
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: "Error del servidor" }); }
});

app.post("/api/admin/productos", authMiddleware, async (req, res) => {
  const nombre      = sanitizeStr(req.body.nombre, 200);
  const descripcion = sanitizeStr(req.body.descripcion, 2000);
  const precio      = parseFloat(req.body.precio);
  const imagen      = req.body.imagen || null;
  const estado      = ["activo","inactivo"].includes(req.body.estado) ? req.body.estado : "activo";
  const stock       = Math.max(0, parseInt(req.body.stock) || 0);

  if (!nombre || !descripcion)
    return res.status(400).json({ error: "Nombre y descripción son requeridos" });
  if (!validatePositiveNum(precio))
    return res.status(400).json({ error: "Precio inválido" });

  try {
    const result = await pool.query(
      `INSERT INTO productos (nombre, descripcion, precio, imagen, stock, estado, fecha_creacion)
       VALUES ($1,$2,$3,$4,$5,$6,NOW()) RETURNING *`,
      [nombre, descripcion, precio, imagen, stock, estado]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: "Error del servidor" }); }
});

app.put("/api/admin/productos/:id", authMiddleware, async (req, res) => {
  const id          = parseInt(req.params.id);
  const nombre      = sanitizeStr(req.body.nombre, 200);
  const descripcion = sanitizeStr(req.body.descripcion, 2000);
  const precio      = parseFloat(req.body.precio);
  const imagen      = req.body.imagen || null;
  const estado      = ["activo","inactivo"].includes(req.body.estado) ? req.body.estado : "activo";
  const stock       = Math.max(0, parseInt(req.body.stock) || 0);

  if (isNaN(id) || !nombre || !descripcion || !validatePositiveNum(precio))
    return res.status(400).json({ error: "Datos inválidos" });

  try {
    await pool.query(
      `UPDATE productos SET nombre=$1, descripcion=$2, precio=$3, imagen=$4, estado=$5, stock=$6 WHERE id=$7`,
      [nombre, descripcion, precio, imagen, estado, stock, id]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: "Error del servidor" }); }
});

app.delete("/api/admin/productos/:id", authMiddleware, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: "ID inválido" });
  try {
    await pool.query("DELETE FROM productos WHERE id=$1", [id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: "Error del servidor" }); }
});

// ── Pedidos ─────────────────────────────────────────────────────
app.post("/api/pedidos", orderLimiter, async (req, res) => {
  const nombre     = sanitizeStr(req.body.nombre, 100);
  const apellido   = sanitizeStr(req.body.apellido, 100);
  const telefono   = sanitizeStr(req.body.telefono, 30);
  const ubicacion  = sanitizeStr(req.body.ubicacion, 500);
  const metodo     = sanitizeStr(req.body.metodo_pago, 50);
  const items      = req.body.items;
  const total      = parseFloat(req.body.total);

  // Validate all fields
  if (!nombre || !apellido || !telefono || !ubicacion || !metodo)
    return res.status(400).json({ error: "Todos los campos del cliente son requeridos" });
  if (!validatePedidoItems(items))
    return res.status(400).json({ error: "Items del pedido inválidos" });
  if (!validatePositiveNum(total) || total > 999999)
    return res.status(400).json({ error: "Total inválido" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Deduct stock with validation
    for (const item of items) {
      const itemId  = parseInt(item.id);
      const itemQty = parseInt(item.cantidad);
      if (isNaN(itemId) || itemId <= 0) continue;

      const prod = await client.query(
        "SELECT stock, nombre FROM productos WHERE id=$1 FOR UPDATE", [itemId]
      );
      if (!prod.rows.length) continue;
      const { stock, nombre: nomProd } = prod.rows[0];
      if (stock !== null && stock < itemQty) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          error: `Stock insuficiente para "${nomProd}". Disponible: ${stock}, solicitado: ${itemQty}`
        });
      }
      if (stock !== null) {
        await client.query(
          "UPDATE productos SET stock = stock - $1 WHERE id=$2", [itemQty, itemId]
        );
      }
    }

    const ped = await client.query(
      `INSERT INTO pedidos (nombre, apellido, telefono, ubicacion, total, metodo_pago, estado, fecha_creacion)
       VALUES ($1,$2,$3,$4,$5,$6,'pendiente',NOW()) RETURNING id`,
      [nombre, apellido, telefono, ubicacion, total, metodo]
    );
    const pedidoId = ped.rows[0].id;

    for (const item of items) {
      const itemId    = parseInt(item.id) > 0 ? parseInt(item.id) : null;
      const itemNom   = sanitizeStr(item.nombre, 200);
      const itemPrecio = parseFloat(item.precio);
      const itemCant  = parseInt(item.cantidad);
      await client.query(
        `INSERT INTO detalle_pedido (pedido_id, producto_id, nombre_producto, precio, cantidad)
         VALUES ($1,$2,$3,$4,$5)`,
        [pedidoId, itemId, itemNom, itemPrecio, itemCant]
      );
    }

    await client.query("COMMIT");
    res.status(201).json({ ok: true, pedidoId });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: "Error del servidor" });
  } finally {
    client.release();
  }
});

app.get("/api/admin/pedidos", authMiddleware, async (req, res) => {
  try {
    // Support search by name or phone
    const search = req.query.search ? `%${req.query.search}%` : null;
    const query  = search
      ? `SELECT * FROM pedidos WHERE nombre ILIKE $1 OR apellido ILIKE $1 OR telefono ILIKE $1 ORDER BY fecha_creacion DESC`
      : `SELECT * FROM pedidos ORDER BY fecha_creacion DESC`;
    const params = search ? [search] : [];

    const pedidos = await pool.query(query, params);
    const result  = await Promise.all(pedidos.rows.map(async p => {
      const items = await pool.query(
        "SELECT nombre_producto, precio, cantidad, producto_id FROM detalle_pedido WHERE pedido_id=$1",
        [p.id]
      );
      return { ...p, items: items.rows };
    }));
    res.json(result);
  } catch (err) { res.status(500).json({ error: "Error del servidor" }); }
});

app.put("/api/admin/pedidos/:id/estado", authMiddleware, async (req, res) => {
  const id         = parseInt(req.params.id);
  const estadoNuevo = req.body.estado;

  if (isNaN(id)) return res.status(400).json({ error: "ID inválido" });
  if (!["pendiente","confirmado","entregado","cancelado"].includes(estadoNuevo))
    return res.status(400).json({ error: "Estado inválido" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const current      = await client.query("SELECT estado FROM pedidos WHERE id=$1", [id]);
    const estadoAnterior = current.rows[0]?.estado;

    // Restore stock on cancel
    if (estadoNuevo === "cancelado" && estadoAnterior !== "cancelado") {
      const detalles = await client.query(
        "SELECT producto_id, cantidad FROM detalle_pedido WHERE pedido_id=$1 AND producto_id IS NOT NULL", [id]
      );
      for (const row of detalles.rows) {
        await client.query(
          "UPDATE productos SET stock = stock + $1 WHERE id=$2", [row.cantidad, row.producto_id]
        );
      }
    }

    // Re-deduct if un-cancelling
    if (estadoAnterior === "cancelado" && estadoNuevo !== "cancelado") {
      const detalles = await client.query(
        "SELECT producto_id, cantidad FROM detalle_pedido WHERE pedido_id=$1 AND producto_id IS NOT NULL", [id]
      );
      for (const row of detalles.rows) {
        await client.query(
          "UPDATE productos SET stock = GREATEST(stock - $1, 0) WHERE id=$2", [row.cantidad, row.producto_id]
        );
      }
    }

    await client.query("UPDATE pedidos SET estado=$1 WHERE id=$2", [estadoNuevo, id]);
    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: "Error del servidor" });
  } finally {
    client.release();
  }
});

// ── Keep-alive (Render free tier) ──────────────────────────────
const http  = require("http");
const https = require("https");
const SELF_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;

setInterval(() => {
  const lib = SELF_URL.startsWith("https") ? https : http;
  lib.get(SELF_URL + "/api/health", () => {}).on("error", () => {});
}, 10 * 60 * 1000);

// ── Start ───────────────────────────────────────────────────────
connectDB().then(initDB).then(() => {
  app.listen(PORT, () => console.log(`🚀 Servidor en puerto ${PORT}`));
});
