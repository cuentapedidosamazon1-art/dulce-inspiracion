const express = require("express");
const cors    = require("cors");
const { Pool } = require("pg");
const bcrypt  = require("bcryptjs");
const jwt     = require("jsonwebtoken");

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "DulceInspiracion2026";

app.use(cors({
  origin: process.env.FRONTEND_URL || "*",
  credentials: true
}));
app.use(express.json({ limit: "20mb" }));

// ── CONEXIÓN POSTGRESQL (Railway / Render) ──────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

async function connectDB() {
  try {
    const client = await pool.connect();
    console.log("✅ Conectado a PostgreSQL correctamente");
    client.release();
  } catch (err) {
    console.log("❌ Error de conexión:", err.message);
    process.exit(1);
  }
}

// ── CREAR TABLAS SI NO EXISTEN ──────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      -- Add stock column to existing installations
    ALTER TABLE productos ADD COLUMN IF NOT EXISTS stock INT NOT NULL DEFAULT 0;

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

    // Crear admin inicial si no existe
    const adminCheck = await client.query(
      "SELECT id FROM usuarios WHERE email = 'admin@dulceinspiracion.com'"
    );
    if (adminCheck.rows.length === 0) {
      const hash = await bcrypt.hash("Admin123!", 10);
      await client.query(
        "INSERT INTO usuarios (nombre, email, password_hash) VALUES ($1, $2, $3)",
        ["Administrador", "admin@dulceinspiracion.com", hash]
      );
      console.log("✅ Usuario admin creado → admin@dulceinspiracion.com / Admin123!");
    }

    // Insertar productos de ejemplo si no existen
    const prodCheck = await client.query("SELECT COUNT(*) FROM productos");
    if (parseInt(prodCheck.rows[0].count) === 0) {
      await client.query(`
        INSERT INTO productos (nombre, descripcion, precio, stock, estado) VALUES
        ('Caja de Bombones Premium', 'Deliciosos bombones de chocolate belga con relleno de trufa y caramelo. Presentación elegante en caja de 12 unidades.', 850, 20, 'activo'),
        ('Paletas Artesanales x6', 'Paletas de frutas tropicales hechas a mano: mango, tamarindo, parcha y más. Perfectas para el calor dominicano.', 320, 30, 'activo'),
        ('Dulces de Leche Surtidos', 'Variedad de dulces de leche tradicionales: con coco, con nuez y clásicos. Bolsa de 500g llena de sabor casero.', 450, 25, 'activo'),
        ('Torta de Chocolate Premium', 'Torta húmeda de chocolate con ganache y decoración artesanal. Tamaño mediano, perfecta para 8-10 personas.', 1200, 10, 'activo'),
        ('Macarons Franceses x12', 'Macarons importados con rellenos de vainilla, frambuesa y pistache. La elegancia europea en tu mesa.', 750, 15, 'activo'),
        ('Kit Candy Bar Fiesta', 'Todo para tu candy bar: gomitas, masmelos, chocolatinas, piruletas y más. Suficiente para 30 personas.', 2200, 8, 'activo')
      `);
      console.log("✅ Productos de ejemplo insertados");
    }

    console.log("✅ Base de datos inicializada correctamente");
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

// ── LOGIN ───────────────────────────────────────────────────────
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query(
      "SELECT * FROM usuarios WHERE email = $1 AND activo = true",
      [email]
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Usuario no encontrado" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Contraseña incorrecta" });
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "8h" }
    );
    res.json({ token, nombre: user.nombre, email: user.email });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PRODUCTOS PÚBLICOS ──────────────────────────────────────────
app.get("/api/productos", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM productos WHERE estado = 'activo' ORDER BY fecha_creacion DESC"
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PRODUCTOS ADMIN ─────────────────────────────────────────────
app.get("/api/admin/productos", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM productos ORDER BY fecha_creacion DESC"
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/admin/productos", authMiddleware, async (req, res) => {
  const { nombre, descripcion, precio, imagen, estado } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO productos (nombre, descripcion, precio, imagen, stock, estado, fecha_creacion)
       VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING *`,
      [nombre, descripcion, precio, imagen, req.body.stock || 0, estado || "activo"]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/admin/productos/:id", authMiddleware, async (req, res) => {
  const { nombre, descripcion, precio, imagen, estado } = req.body;
  try {
    await pool.query(
      `UPDATE productos SET nombre=$1, descripcion=$2, precio=$3, imagen=$4, estado=$5, stock=$6
       WHERE id=$7`,
      [nombre, descripcion, precio, imagen, estado, req.body.stock !== undefined ? req.body.stock : 0, req.params.id]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/admin/productos/:id", authMiddleware, async (req, res) => {
  try {
    await pool.query("DELETE FROM productos WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PEDIDOS ─────────────────────────────────────────────────────
app.post("/api/pedidos", async (req, res) => {
  const { nombre, apellido, telefono, ubicacion, items, total, metodo_pago } = req.body;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // ── Verificar y rebajar stock de cada producto ──
    for (const item of items) {
      if (!item.id || typeof item.id !== "number") continue; // skip combos/non-db items
      const prod = await client.query(
        "SELECT stock, nombre FROM productos WHERE id=$1 FOR UPDATE",
        [item.id]
      );
      if (!prod.rows.length) continue;
      const { stock, nombre } = prod.rows[0];
      if (stock !== null && stock < item.cantidad) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          error: `Stock insuficiente para "${nombre}". Disponible: ${stock}, solicitado: ${item.cantidad}`
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
    const pedidos = await pool.query(
      "SELECT * FROM pedidos ORDER BY fecha_creacion DESC"
    );
    const result = await Promise.all(
      pedidos.rows.map(async (p) => {
        const items = await pool.query(
          "SELECT nombre_producto, precio, cantidad, producto_id FROM detalle_pedido WHERE pedido_id = $1",
          [p.id]
        );
        return { ...p, items: items.rows };
      })
    );
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/admin/pedidos/:id/estado", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Get current state before updating
    const current = await client.query(
      "SELECT estado FROM pedidos WHERE id=$1",
      [req.params.id]
    );
    const estadoAnterior = current.rows[0]?.estado;
    const estadoNuevo    = req.body.estado;

    // ── If cancelling: restore stock ──
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

    // ── If un-cancelling (e.g. back to pendiente): deduct stock again ──
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

    await client.query(
      "UPDATE pedidos SET estado=$1 WHERE id=$2",
      [estadoNuevo, req.params.id]
    );

    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ── HEALTH CHECK ────────────────────────────────────────────────
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ── INICIAR ─────────────────────────────────────────────────────

// ── KEEP-ALIVE — evita que Render se duerma (plan gratis) ──────
// Hace un ping a sí mismo cada 10 minutos
const SELF_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
setInterval(async () => {
  try {
    const https = require('https');
    const http  = require('http');
    const lib   = SELF_URL.startsWith('https') ? https : http;
    lib.get(SELF_URL + '/api/health', () => {}).on('error', () => {});
  } catch(e) { /* silent */ }
}, 10 * 60 * 1000); // cada 10 minutos

connectDB().then(initDB).then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  });
});
