const express = require("express");
const cors    = require("cors");
const { Pool } = require("pg");
const bcrypt  = require("bcryptjs");
const jwt     = require("jsonwebtoken");

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "DulceInspiracion2026";

app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.options("*", cors());
app.use(express.json({ limit: "20mb" }));

// ── CONEXIÓN POSTGRESQL ─────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

async function connectDB() {
  try {
    const client = await pool.connect();
    console.log("✅ Conectado a PostgreSQL");
    client.release();
  } catch (err) {
    console.log("❌ Error de conexión:", err.message);
    process.exit(1);
  }
}

// ── CREAR TABLAS + DATOS INICIALES ──────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    // Agregar columna stock si no existe (migración)
    await client.query(`
      ALTER TABLE productos ADD COLUMN IF NOT EXISTS stock INT NOT NULL DEFAULT 0;
    `).catch(() => {});

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
        precio         DECIMAL(10,2) NOT NULL,
        imagen         TEXT NULL,
        stock          INT NOT NULL DEFAULT 0,
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
        total          DECIMAL(10,2) NOT NULL,
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
        precio          DECIMAL(10,2) NOT NULL,
        cantidad        INT NOT NULL DEFAULT 1
      );
    `);

    // Admin inicial
    const adminCheck = await client.query(
      "SELECT id FROM usuarios WHERE email = 'admin@dulceinspiracion.com'"
    );
    if (adminCheck.rows.length === 0) {
      const hash = await bcrypt.hash("Admin123!", 10);
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
  } catch {
    res.status(401).json({ error: "Token inválido o expirado" });
  }
}

// ══════════════════════════════════════════════════════════════
//  RUTAS
// ══════════════════════════════════════════════════════════════

// ── HEALTH CHECK ────────────────────────────────────────────────
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ── LOGIN ───────────────────────────────────────────────────────
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query(
      "SELECT * FROM usuarios WHERE email=$1 AND activo=true", [email]
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Usuario no encontrado" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Contraseña incorrecta" });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "8h" });
    res.json({ token, nombre: user.nombre, email: user.email });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── USUARIOS ADMIN ──────────────────────────────────────────────
app.get("/api/admin/usuarios", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, nombre, email, activo, fecha_creacion FROM usuarios ORDER BY fecha_creacion ASC"
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/admin/usuarios", authMiddleware, async (req, res) => {
  const { nombre, email, password } = req.body;
  if (!nombre || !email || !password)
    return res.status(400).json({ error: "Todos los campos son requeridos" });
  if (password.length < 8)
    return res.status(400).json({ error: "La contraseña debe tener al menos 8 caracteres" });
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO usuarios (nombre, email, password_hash) VALUES ($1,$2,$3) RETURNING id, nombre, email",
      [nombre, email, hash]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") return res.status(400).json({ error: "Ese email ya está registrado" });
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/admin/usuarios/:id", authMiddleware, async (req, res) => {
  if (parseInt(req.params.id) === req.user.id)
    return res.status(400).json({ error: "No puedes eliminarte a ti mismo" });
  try {
    await pool.query("DELETE FROM usuarios WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── PRODUCTOS PÚBLICOS ──────────────────────────────────────────
app.get("/api/productos", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM productos WHERE estado='activo' ORDER BY fecha_creacion DESC"
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── PRODUCTOS ADMIN ─────────────────────────────────────────────
app.get("/api/admin/productos", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM productos ORDER BY fecha_creacion DESC");
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/admin/productos", authMiddleware, async (req, res) => {
  const { nombre, descripcion, precio, imagen, estado, stock } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO productos (nombre, descripcion, precio, imagen, stock, estado, fecha_creacion)
       VALUES ($1,$2,$3,$4,$5,$6,NOW()) RETURNING *`,
      [nombre, descripcion, precio, imagen, stock || 0, estado || "activo"]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put("/api/admin/productos/:id", authMiddleware, async (req, res) => {
  const { nombre, descripcion, precio, imagen, estado, stock } = req.body;
  try {
    await pool.query(
      `UPDATE productos SET nombre=$1, descripcion=$2, precio=$3, imagen=$4, estado=$5, stock=$6 WHERE id=$7`,
      [nombre, descripcion, precio, imagen, estado, stock !== undefined ? stock : 0, req.params.id]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete("/api/admin/productos/:id", authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM productos WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── PEDIDOS ─────────────────────────────────────────────────────
app.post("/api/pedidos", async (req, res) => {
  const { nombre, apellido, telefono, ubicacion, items, total, metodo_pago } = req.body;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Verificar y rebajar stock
    for (const item of items) {
      if (!item.id || typeof item.id !== "number") continue;
      const prod = await client.query(
        "SELECT stock, nombre FROM productos WHERE id=$1 FOR UPDATE", [item.id]
      );
      if (!prod.rows.length) continue;
      const { stock, nombre: nomProd } = prod.rows[0];
      if (stock !== null && stock < item.cantidad) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          error: `Stock insuficiente para "${nomProd}". Disponible: ${stock}, solicitado: ${item.cantidad}`
        });
      }
      if (stock !== null) {
        await client.query(
          "UPDATE productos SET stock = stock - $1 WHERE id=$2",
          [item.cantidad, item.id]
        );
      }
    }

    const ped = await client.query(
      `INSERT INTO pedidos (nombre, apellido, telefono, ubicacion, total, metodo_pago, estado, fecha_creacion)
       VALUES ($1,$2,$3,$4,$5,$6,'pendiente',NOW()) RETURNING id`,
      [nombre, apellido, telefono, ubicacion, total, metodo_pago]
    );
    const pedidoId = ped.rows[0].id;

    for (const item of items) {
      await client.query(
        `INSERT INTO detalle_pedido (pedido_id, producto_id, nombre_producto, precio, cantidad)
         VALUES ($1,$2,$3,$4,$5)`,
        [pedidoId, item.id || null, item.nombre, item.precio, item.cantidad]
      );
    }

    await client.query("COMMIT");
    res.status(201).json({ ok: true, pedidoId });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.get("/api/admin/pedidos", authMiddleware, async (req, res) => {
  try {
    const pedidos = await pool.query("SELECT * FROM pedidos ORDER BY fecha_creacion DESC");
    const result  = await Promise.all(pedidos.rows.map(async (p) => {
      const items = await pool.query(
        "SELECT nombre_producto, precio, cantidad, producto_id FROM detalle_pedido WHERE pedido_id=$1",
        [p.id]
      );
      return { ...p, items: items.rows };
    }));
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put("/api/admin/pedidos/:id/estado", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const current = await client.query(
      "SELECT estado FROM pedidos WHERE id=$1", [req.params.id]
    );
    const estadoAnterior = current.rows[0]?.estado;
    const estadoNuevo    = req.body.estado;

    // Cancelar → restaurar stock
    if (estadoNuevo === "cancelado" && estadoAnterior !== "cancelado") {
      const detalles = await client.query(
        "SELECT producto_id, cantidad FROM detalle_pedido WHERE pedido_id=$1 AND producto_id IS NOT NULL",
        [req.params.id]
      );
      for (const row of detalles.rows) {
        await client.query(
          "UPDATE productos SET stock = stock + $1 WHERE id=$2",
          [row.cantidad, row.producto_id]
        );
      }
    }

    // Reactivar desde cancelado → rebajar stock de nuevo
    if (estadoAnterior === "cancelado" && estadoNuevo !== "cancelado") {
      const detalles = await client.query(
        "SELECT producto_id, cantidad FROM detalle_pedido WHERE pedido_id=$1 AND producto_id IS NOT NULL",
        [req.params.id]
      );
      for (const row of detalles.rows) {
        await client.query(
          "UPDATE productos SET stock = GREATEST(stock - $1, 0) WHERE id=$2",
          [row.cantidad, row.producto_id]
        );
      }
    }

    await client.query("UPDATE pedidos SET estado=$1 WHERE id=$2", [estadoNuevo, req.params.id]);
    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ── KEEP-ALIVE (evita que Render se duerma) ─────────────────────
const SELF_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
setInterval(() => {
  try {
    const lib = SELF_URL.startsWith("https") ? require("https") : require("http");
    lib.get(SELF_URL + "/api/health", () => {}).on("error", () => {});
  } catch(e) {}
}, 10 * 60 * 1000);

// ── INICIAR ─────────────────────────────────────────────────────
connectDB().then(initDB).then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  });
});
