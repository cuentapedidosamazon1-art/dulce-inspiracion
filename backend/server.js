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
    // Migraciones seguras
    await client.query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS stock INT NOT NULL DEFAULT 0;`).catch(() => {});
    await client.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS rol VARCHAR(20) NOT NULL DEFAULT 'editor';`).catch(() => {});
    await client.query(`ALTER TABLE entradas_inventario ADD COLUMN IF NOT EXISTS fecha DATE NOT NULL DEFAULT CURRENT_DATE;`).catch(() => {});
    await client.query(`ALTER TABLE entradas_inventario ADD COLUMN IF NOT EXISTS proveedor VARCHAR(200) NULL;`).catch(() => {});
    await client.query(`ALTER TABLE entradas_inventario ADD COLUMN IF NOT EXISTS factura VARCHAR(100) NULL;`).catch(() => {});
    await client.query(`ALTER TABLE entradas_inventario ADD COLUMN IF NOT EXISTS notas TEXT NULL;`).catch(() => {});
    // El primer usuario (admin) siempre es admin
    await client.query(`UPDATE usuarios SET rol='admin' WHERE email='admin@dulceinspiracion.com';`).catch(() => {});

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

      CREATE TABLE IF NOT EXISTS entradas_inventario (
        id            SERIAL PRIMARY KEY,
        producto_id   INT NOT NULL REFERENCES productos(id) ON DELETE CASCADE,
        cantidad      INT NOT NULL CHECK (cantidad > 0),
        precio_compra DECIMAL(10,2) NOT NULL CHECK (precio_compra > 0),
        proveedor     VARCHAR(200) NULL,
        factura       VARCHAR(100) NULL,
        notas         TEXT NULL,
        fecha         DATE NOT NULL,
        fecha_creacion TIMESTAMP NOT NULL DEFAULT NOW()
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
    const token = jwt.sign({ id: user.id, email: user.email, rol: user.rol || 'editor' }, JWT_SECRET, { expiresIn: "8h" });
    res.json({ token, nombre: user.nombre, email: user.email, rol: user.rol || 'editor' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── USUARIOS ADMIN ──────────────────────────────────────────────
app.get("/api/admin/usuarios", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, nombre, email, rol, activo, fecha_creacion FROM usuarios ORDER BY fecha_creacion ASC"
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/admin/usuarios", authMiddleware, async (req, res) => {
  const { nombre, email, password, rol } = req.body;
  if (!nombre || !email || !password)
    return res.status(400).json({ error: "Todos los campos son requeridos" });
  if (password.length < 8)
    return res.status(400).json({ error: "La contraseña debe tener al menos 8 caracteres" });
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO usuarios (nombre, email, password_hash, rol) VALUES ($1,$2,$3,$4) RETURNING id, nombre, email, rol",
      [nombre, email, hash, rol || 'editor']
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

// ── ESTADÍSTICAS ADMIN ─────────────────────────────────────────
app.get("/api/admin/estadisticas", authMiddleware, async (req, res) => {
  try {
    const totalesRes = await pool.query(`
      SELECT
        COUNT(*)::int                                             AS total_pedidos,
        COALESCE(SUM(total), 0)::float                           AS ingresos_totales,
        COUNT(*) FILTER (WHERE estado = 'pendiente')::int        AS pendientes,
        COUNT(*) FILTER (WHERE estado = 'entregado')::int        AS entregados
      FROM pedidos
      WHERE estado != 'cancelado'
    `);

    const masRes = await pool.query(`
      SELECT p.id, p.nombre, p.precio::float, p.imagen,
        SUM(dp.cantidad)::int                    AS total_vendido,
        SUM(dp.cantidad * dp.precio)::float      AS ingresos_total,
        COUNT(DISTINCT dp.pedido_id)::int        AS num_pedidos
      FROM productos p
      JOIN detalle_pedido dp ON dp.producto_id = p.id
      JOIN pedidos pe        ON pe.id = dp.pedido_id AND pe.estado != 'cancelado'
      GROUP BY p.id, p.nombre, p.precio, p.imagen
      ORDER BY total_vendido DESC
      LIMIT 1
    `);

    const menosRes = await pool.query(`
      SELECT p.id, p.nombre, p.precio::float, p.imagen,
        SUM(dp.cantidad)::int                              AS total_vendido,
        SUM(dp.cantidad * dp.precio)::float                AS ingresos_total,
        EXTRACT(DAY FROM NOW() - p.fecha_creacion)::int    AS dias_en_inventario
      FROM productos p
      JOIN detalle_pedido dp ON dp.producto_id = p.id
      JOIN pedidos pe        ON pe.id = dp.pedido_id AND pe.estado != 'cancelado'
      GROUP BY p.id, p.nombre, p.precio, p.imagen, p.fecha_creacion
      ORDER BY total_vendido ASC
      LIMIT 1
    `);

    res.json({
      totales:      totalesRes.rows[0] || { total_pedidos:0, ingresos_totales:0, pendientes:0, entregados:0 },
      masVendido:   masRes.rows[0]     || null,
      menosVendido: menosRes.rows[0]   || null,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


// ── ENTRADAS DE INVENTARIO ──────────────────────────────────────

// GET /api/admin/entradas  → historial completo (con nombre de producto)
app.get("/api/admin/entradas", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        e.id,
        e.producto_id,
        p.nombre            AS producto_nombre,
        p.precio            AS precio_venta,
        e.cantidad,
        e.precio_compra,
        e.proveedor,
        e.factura,
        e.notas,
        e.fecha,
        e.fecha_creacion,
        ROUND(
          ((p.precio - e.precio_compra) / NULLIF(p.precio, 0)) * 100, 1
        )::float            AS margen_pct
      FROM entradas_inventario e
      JOIN productos p ON p.id = e.producto_id
      ORDER BY e.fecha_creacion DESC
    `);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/admin/entradas/:id  → una entrada especifica
app.get("/api/admin/entradas/:id", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT e.*, p.nombre AS producto_nombre, p.precio AS precio_venta
      FROM entradas_inventario e
      JOIN productos p ON p.id = e.producto_id
      WHERE e.id = $1
    `, [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: "Entrada no encontrada" });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/admin/entradas  → registrar entrada y actualizar stock atomicamente
app.post("/api/admin/entradas", authMiddleware, async (req, res) => {
  const { producto_id, cantidad, precio_compra, fecha, proveedor, factura, notas } = req.body;

  if (!producto_id)
    return res.status(400).json({ error: "producto_id es requerido" });
  if (!cantidad || parseInt(cantidad) < 1)
    return res.status(400).json({ error: "La cantidad debe ser mayor a 0" });
  if (!precio_compra || parseFloat(precio_compra) <= 0)
    return res.status(400).json({ error: "precio_compra debe ser mayor a 0" });
  if (!fecha)
    return res.status(400).json({ error: "La fecha es requerida" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Verificar que el producto existe
    const prodRes = await client.query(
      "SELECT id, nombre, stock FROM productos WHERE id = $1", [producto_id]
    );
    if (!prodRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Producto no encontrado" });
    }

    // Insertar registro de entrada
    const entrada = await client.query(`
      INSERT INTO entradas_inventario
        (producto_id, cantidad, precio_compra, proveedor, factura, notas, fecha)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
    `, [
      producto_id,
      parseInt(cantidad),
      parseFloat(precio_compra),
      proveedor || null,
      factura   || null,
      notas     || null,
      fecha
    ]);

    // Actualizar stock del producto atomicamente
    const stockRes = await client.query(
      "UPDATE productos SET stock = stock + $1 WHERE id = $2 RETURNING stock",
      [parseInt(cantidad), producto_id]
    );

    await client.query("COMMIT");

    res.status(201).json({
      ok: true,
      entrada: entrada.rows[0],
      stock_nuevo: stockRes.rows[0].stock
    });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// DELETE /api/admin/entradas/:id  → eliminar entrada y revertir stock
app.delete("/api/admin/entradas/:id", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Obtener la entrada antes de borrarla
    const entRes = await client.query(
      "SELECT producto_id, cantidad FROM entradas_inventario WHERE id = $1",
      [req.params.id]
    );
    if (!entRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Entrada no encontrada" });
    }

    const { producto_id, cantidad } = entRes.rows[0];

    // Revertir el stock (no bajar de 0)
    await client.query(
      "UPDATE productos SET stock = GREATEST(stock - $1, 0) WHERE id = $2",
      [cantidad, producto_id]
    );

    // Eliminar la entrada
    await client.query("DELETE FROM entradas_inventario WHERE id = $1", [req.params.id]);

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
