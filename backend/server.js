const express = require("express");
const cors    = require("cors");
const { Pool } = require("pg");
const bcrypt  = require("bcryptjs");
const jwt     = require("jsonwebtoken");

const app  = express();
const PORT = process.env.PORT || 3000;

// FIX #1: JWT_SECRET nunca usa fallback inseguro en producción
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("❌ FATAL: La variable de entorno JWT_SECRET no está definida.");
  process.exit(1);
}

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
    console.error("❌ Error de conexión:", err.message);
    process.exit(1);
  }
}

// ── CREAR TABLAS + DATOS INICIALES ──────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {

    // ── PASO 1: Crear tablas primero (seguro con IF NOT EXISTS) ──
    // FIX #2: Las tablas se crean ANTES de intentar alterarlas
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

      CREATE TABLE IF NOT EXISTS ventas_tienda (
        id              SERIAL PRIMARY KEY,
        numero_factura  VARCHAR(30) NOT NULL UNIQUE,
        usuario_id      INT NULL REFERENCES usuarios(id) ON DELETE SET NULL,
        cliente_nombre  VARCHAR(200) NULL,
        subtotal        DECIMAL(10,2) NOT NULL,
        descuento_pct   DECIMAL(5,2) NOT NULL DEFAULT 0,
        descuento_monto DECIMAL(10,2) NOT NULL DEFAULT 0,
        itbis           DECIMAL(10,2) NOT NULL DEFAULT 0,
        total           DECIMAL(10,2) NOT NULL,
        metodo_pago     VARCHAR(50)  NOT NULL DEFAULT 'Efectivo',
        monto_recibido  DECIMAL(10,2) NULL,
        cambio          DECIMAL(10,2) NULL,
        notas           TEXT NULL,
        estado          VARCHAR(20)  NOT NULL DEFAULT 'completada'
                        CHECK (estado IN ('completada','anulada')),
        fecha_creacion  TIMESTAMP NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS detalle_venta_tienda (
        id              SERIAL PRIMARY KEY,
        venta_id        INT NOT NULL REFERENCES ventas_tienda(id) ON DELETE CASCADE,
        producto_id     INT NULL REFERENCES productos(id) ON DELETE SET NULL,
        nombre_producto VARCHAR(200) NOT NULL,
        precio_unitario DECIMAL(10,2) NOT NULL,
        cantidad        INT NOT NULL DEFAULT 1,
        subtotal        DECIMAL(10,2) NOT NULL
      );

      CREATE TABLE IF NOT EXISTS entradas_inventario (
        id             SERIAL PRIMARY KEY,
        producto_id    INT NOT NULL REFERENCES productos(id) ON DELETE CASCADE,
        usuario_id     INT NULL,
        cantidad       INT NOT NULL CHECK (cantidad > 0),
        precio_compra  DECIMAL(10,2) NOT NULL CHECK (precio_compra > 0),
        proveedor      VARCHAR(200) NULL,
        factura        VARCHAR(100) NULL,
        notas          TEXT NULL,
        fecha          DATE NOT NULL,
        fecha_creacion TIMESTAMP NOT NULL DEFAULT NOW()
      );
    `);

    // ── PASO 2: Migraciones sobre tablas ya existentes ───────────
    // Agregar columnas nuevas si no existen (deploy en BD legacy)
    await client.query(`ALTER TABLE productos ADD COLUMN IF NOT EXISTS stock INT NOT NULL DEFAULT 0;`).catch(() => {});
    await client.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS rol VARCHAR(20) NOT NULL DEFAULT 'editor';`).catch(() => {});
    await client.query(`ALTER TABLE entradas_inventario ADD COLUMN IF NOT EXISTS usuario_id INT NULL;`).catch(() => {});

    // Renombrar columnas con mayúsculas → minúsculas (solo si existen)
    await client.query(`ALTER TABLE entradas_inventario RENAME COLUMN "Proveedor" TO proveedor;`).catch(() => {});
    await client.query(`ALTER TABLE entradas_inventario RENAME COLUMN "Factura"   TO factura;`).catch(() => {});
    await client.query(`ALTER TABLE entradas_inventario RENAME COLUMN "Notas"     TO notas;`).catch(() => {});
    await client.query(`ALTER TABLE entradas_inventario RENAME COLUMN fecha_registro TO fecha_creacion;`).catch(() => {});

    // Migración fecha_entrada → fecha:
    // Caso A: existe fecha_entrada pero NO fecha → renombrar
    await client.query(`
      DO $$ BEGIN
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name='entradas_inventario' AND column_name='fecha_entrada'
        ) AND NOT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name='entradas_inventario' AND column_name='fecha'
        ) THEN
          ALTER TABLE entradas_inventario RENAME COLUMN fecha_entrada TO fecha;
        END IF;
      END $$;
    `).catch(() => {});

    // Caso B: existen AMBAS (fecha_entrada y fecha) → copiar datos y soltar fecha_entrada
    await client.query(`
      DO $$ BEGIN
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name='entradas_inventario' AND column_name='fecha_entrada'
        ) AND EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name='entradas_inventario' AND column_name='fecha'
        ) THEN
          UPDATE entradas_inventario SET fecha = fecha_entrada WHERE fecha IS NULL AND fecha_entrada IS NOT NULL;
          ALTER TABLE entradas_inventario ALTER COLUMN fecha_entrada DROP NOT NULL;
          ALTER TABLE entradas_inventario DROP COLUMN fecha_entrada;
        END IF;
      END $$;
    `).catch(() => {});

    // Garantizar columna fecha (por si la tabla era legacy sin ella)
    await client.query(`ALTER TABLE entradas_inventario ADD COLUMN IF NOT EXISTS fecha DATE;`).catch(() => {});

    // Garantizar que el primer admin siempre tenga rol admin
    await client.query(`UPDATE usuarios SET rol='admin' WHERE email='admin@dulceinspiracion.com';`).catch(() => {});

    // ── PASO 3: Datos iniciales ──────────────────────────────────

    // Admin inicial
    const adminCheck = await client.query(
      "SELECT id FROM usuarios WHERE email = 'admin@dulceinspiracion.com'"
    );
    if (adminCheck.rows.length === 0) {
      const hash = await bcrypt.hash("Admin123!", 10);
      await client.query(
        "INSERT INTO usuarios (nombre, email, password_hash, rol) VALUES ($1,$2,$3,$4)",
        ["Administrador", "admin@dulceinspiracion.com", hash, "admin"]
      );
      console.log("✅ Admin creado → admin@dulceinspiracion.com / Admin123!");
    }

    // Productos de ejemplo (solo si la tabla está vacía)
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
  if (!email || !password)
    return res.status(400).json({ error: "Email y contraseña son requeridos" });
  try {
    const result = await pool.query(
      "SELECT * FROM usuarios WHERE email=$1 AND activo=true", [email]
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Usuario no encontrado" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Contraseña incorrecta" });
    const token = jwt.sign(
      { id: user.id, email: user.email, rol: user.rol || "editor" },
      JWT_SECRET,
      { expiresIn: "8h" }
    );
    res.json({ token, nombre: user.nombre, email: user.email, rol: user.rol || "editor" });
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
      [nombre, email, hash, rol || "editor"]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") return res.status(400).json({ error: "Ese email ya está registrado" });
    res.status(500).json({ error: err.message });
  }
});

// FIX #3: DELETE usuario verifica que exista antes de responder ok
app.delete("/api/admin/usuarios/:id", authMiddleware, async (req, res) => {
  if (parseInt(req.params.id) === req.user.id)
    return res.status(400).json({ error: "No puedes eliminarte a ti mismo" });
  try {
    const result = await pool.query(
      "DELETE FROM usuarios WHERE id=$1 RETURNING id", [req.params.id]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "Usuario no encontrado" });
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
  if (!nombre || !descripcion || !precio)
    return res.status(400).json({ error: "nombre, descripcion y precio son requeridos" });
  try {
    const result = await pool.query(
      `INSERT INTO productos (nombre, descripcion, precio, imagen, stock, estado, fecha_creacion)
       VALUES ($1,$2,$3,$4,$5,$6,NOW()) RETURNING *`,
      [nombre, descripcion, precio, imagen || null, stock || 0, estado || "activo"]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put("/api/admin/productos/:id", authMiddleware, async (req, res) => {
  const { nombre, descripcion, precio, imagen, estado, stock } = req.body;
  if (!nombre || !descripcion || !precio)
    return res.status(400).json({ error: "nombre, descripcion y precio son requeridos" });
  try {
    const result = await pool.query(
      `UPDATE productos SET nombre=$1, descripcion=$2, precio=$3, imagen=$4, estado=$5, stock=$6 WHERE id=$7 RETURNING id`,
      [nombre, descripcion, precio, imagen || null, estado, stock !== undefined ? stock : 0, req.params.id]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "Producto no encontrado" });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete("/api/admin/productos/:id", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM productos WHERE id=$1 RETURNING id", [req.params.id]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "Producto no encontrado" });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── PEDIDOS ─────────────────────────────────────────────────────
app.post("/api/pedidos", async (req, res) => {
  const { nombre, apellido, telefono, ubicacion, items, total, metodo_pago } = req.body;

  if (!nombre || !apellido || !telefono || !ubicacion || !metodo_pago)
    return res.status(400).json({ error: "Todos los datos del cliente son requeridos" });
  if (!Array.isArray(items) || items.length === 0)
    return res.status(400).json({ error: "El pedido debe tener al menos un producto" });

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

// FIX #4: GET pedidos con JOIN en lugar de N+1 queries
app.get("/api/admin/pedidos", authMiddleware, async (req, res) => {
  try {
    const pedidos = await pool.query("SELECT * FROM pedidos ORDER BY fecha_creacion DESC");
    if (pedidos.rows.length === 0) return res.json([]);

    const pedidoIds = pedidos.rows.map(p => p.id);
    const detalles  = await pool.query(
      `SELECT pedido_id, nombre_producto, precio, cantidad, producto_id
       FROM detalle_pedido
       WHERE pedido_id = ANY($1)`,
      [pedidoIds]
    );

    // Agrupar detalles por pedido_id
    const detalleMap = {};
    for (const row of detalles.rows) {
      if (!detalleMap[row.pedido_id]) detalleMap[row.pedido_id] = [];
      detalleMap[row.pedido_id].push(row);
    }

    const result = pedidos.rows.map(p => ({
      ...p,
      items: detalleMap[p.id] || []
    }));

    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put("/api/admin/pedidos/:id/estado", authMiddleware, async (req, res) => {
  const estadoNuevo = req.body.estado;
  const estadosValidos = ["pendiente", "confirmado", "entregado", "cancelado"];
  if (!estadosValidos.includes(estadoNuevo))
    return res.status(400).json({ error: "Estado no válido" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const current = await client.query(
      "SELECT estado FROM pedidos WHERE id=$1", [req.params.id]
    );
    if (!current.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Pedido no encontrado" });
    }
    const estadoAnterior = current.rows[0].estado;

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

// ── ESTADÍSTICAS ADMIN (unificadas: pedidos online + POS) ──────
app.get("/api/admin/estadisticas", authMiddleware, async (req, res) => {
  try {
    // ── Totales de pedidos ONLINE ────────────────────────────────
    const totalesRes = await pool.query(`
      SELECT
        COUNT(*)::int                                             AS total_pedidos,
        COALESCE(SUM(total), 0)::float                           AS ingresos_totales,
        COUNT(*) FILTER (WHERE estado = 'pendiente')::int        AS pendientes,
        COUNT(*) FILTER (WHERE estado = 'entregado')::int        AS entregados
      FROM pedidos
      WHERE estado != 'cancelado'
    `);

    // ── Totales de ventas POS ────────────────────────────────────
    const posRes = await pool.query(`
      SELECT
        COUNT(*)::int                                              AS total_ventas_pos,
        COALESCE(SUM(total) FILTER (WHERE estado='completada'),0)::float  AS ingresos_pos,
        COUNT(*) FILTER (WHERE estado='completada')::int           AS completadas_pos,
        COUNT(*) FILTER (WHERE estado='anulada')::int              AS anuladas_pos,
        COALESCE(SUM(total) FILTER (WHERE metodo_pago='Efectivo'       AND estado='completada'),0)::float AS pos_efectivo,
        COALESCE(SUM(total) FILTER (WHERE metodo_pago='Tarjeta'        AND estado='completada'),0)::float AS pos_tarjeta,
        COALESCE(SUM(total) FILTER (WHERE metodo_pago='Transferencia'  AND estado='completada'),0)::float AS pos_transferencia
      FROM ventas_tienda
    `);

    // ── Resumen KPIs de hoy (POS) ────────────────────────────────
    const hoy = new Date().toISOString().slice(0,10);
    const posHoyRes = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE estado='completada')::int                  AS ventas_hoy,
        COALESCE(SUM(total) FILTER (WHERE estado='completada'),0)::float  AS ingresos_hoy,
        COALESCE(SUM(total) FILTER (WHERE metodo_pago='Efectivo' AND estado='completada'),0)::float AS efectivo_hoy,
        COALESCE(SUM(total) FILTER (WHERE metodo_pago='Tarjeta'  AND estado='completada'),0)::float AS tarjeta_hoy,
        COALESCE(SUM(total) FILTER (WHERE metodo_pago='Transferencia' AND estado='completada'),0)::float AS transferencia_hoy
      FROM ventas_tienda
      WHERE DATE(fecha_creacion) = $1
    `, [hoy]);

    // ── Ingresos de hoy pedidos ONLINE ───────────────────────────
    const onlineHoyRes = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE estado IN ('confirmado','entregado'))::int AS pedidos_hoy,
        COALESCE(SUM(total) FILTER (WHERE estado IN ('confirmado','entregado')),0)::float AS ingresos_hoy_online
      FROM pedidos
      WHERE DATE(fecha_creacion) = $1
    `, [hoy]);

    // ── Producto más vendido (pedidos + POS combinados) ──────────
    const masRes = await pool.query(`
      SELECT p.id, p.nombre, p.precio::float, p.imagen,
        SUM(ventas.qty)::int        AS total_vendido,
        SUM(ventas.ingresos)::float AS ingresos_total,
        SUM(ventas.num_tx)::int     AS num_pedidos
      FROM productos p
      JOIN (
        -- Ventas online
        SELECT dp.producto_id,
               SUM(dp.cantidad)                AS qty,
               SUM(dp.cantidad * dp.precio)    AS ingresos,
               COUNT(DISTINCT dp.pedido_id)    AS num_tx
        FROM detalle_pedido dp
        JOIN pedidos pe ON pe.id = dp.pedido_id AND pe.estado != 'cancelado'
        WHERE dp.producto_id IS NOT NULL
        GROUP BY dp.producto_id
        UNION ALL
        -- Ventas POS
        SELECT dvt.producto_id,
               SUM(dvt.cantidad)               AS qty,
               SUM(dvt.subtotal)               AS ingresos,
               COUNT(DISTINCT dvt.venta_id)    AS num_tx
        FROM detalle_venta_tienda dvt
        JOIN ventas_tienda vt ON vt.id = dvt.venta_id AND vt.estado = 'completada'
        WHERE dvt.producto_id IS NOT NULL
        GROUP BY dvt.producto_id
      ) ventas ON ventas.producto_id = p.id
      GROUP BY p.id, p.nombre, p.precio, p.imagen
      ORDER BY total_vendido DESC
      LIMIT 1
    `);

    // ── Producto menos vendido (pedidos + POS combinados) ────────
    const menosRes = await pool.query(`
      SELECT p.id, p.nombre, p.precio::float, p.imagen,
        SUM(ventas.qty)::int        AS total_vendido,
        SUM(ventas.ingresos)::float AS ingresos_total,
        EXTRACT(DAY FROM NOW() - p.fecha_creacion)::int AS dias_en_inventario
      FROM productos p
      JOIN (
        SELECT dp.producto_id,
               SUM(dp.cantidad)             AS qty,
               SUM(dp.cantidad * dp.precio) AS ingresos
        FROM detalle_pedido dp
        JOIN pedidos pe ON pe.id = dp.pedido_id AND pe.estado != 'cancelado'
        WHERE dp.producto_id IS NOT NULL
        GROUP BY dp.producto_id
        UNION ALL
        SELECT dvt.producto_id,
               SUM(dvt.cantidad)  AS qty,
               SUM(dvt.subtotal)  AS ingresos
        FROM detalle_venta_tienda dvt
        JOIN ventas_tienda vt ON vt.id = dvt.venta_id AND vt.estado = 'completada'
        WHERE dvt.producto_id IS NOT NULL
        GROUP BY dvt.producto_id
      ) ventas ON ventas.producto_id = p.id
      GROUP BY p.id, p.nombre, p.precio, p.imagen, p.fecha_creacion
      ORDER BY total_vendido ASC
      LIMIT 1
    `);

    // ── Top 5 productos más vendidos (combinados) ────────────────
    const top5Res = await pool.query(`
      SELECT p.id, p.nombre, p.precio::float, p.imagen,
        SUM(ventas.qty)::int        AS total_vendido,
        SUM(ventas.ingresos)::float AS ingresos_total
      FROM productos p
      JOIN (
        SELECT dp.producto_id, SUM(dp.cantidad) AS qty, SUM(dp.cantidad * dp.precio) AS ingresos
        FROM detalle_pedido dp
        JOIN pedidos pe ON pe.id = dp.pedido_id AND pe.estado != 'cancelado'
        WHERE dp.producto_id IS NOT NULL GROUP BY dp.producto_id
        UNION ALL
        SELECT dvt.producto_id, SUM(dvt.cantidad) AS qty, SUM(dvt.subtotal) AS ingresos
        FROM detalle_venta_tienda dvt
        JOIN ventas_tienda vt ON vt.id = dvt.venta_id AND vt.estado = 'completada'
        WHERE dvt.producto_id IS NOT NULL GROUP BY dvt.producto_id
      ) ventas ON ventas.producto_id = p.id
      GROUP BY p.id, p.nombre, p.precio, p.imagen
      ORDER BY total_vendido DESC LIMIT 5
    `);

    // ── Métodos de pago unificados ───────────────────────────────
    const metodosPagosRes = await pool.query(`
      SELECT metodo_pago, SUM(total)::float AS total, COUNT(*)::int AS cantidad
      FROM (
        SELECT metodo_pago, total FROM pedidos
        WHERE estado IN ('confirmado','entregado')
        UNION ALL
        SELECT metodo_pago, total FROM ventas_tienda
        WHERE estado = 'completada'
      ) t
      GROUP BY metodo_pago
      ORDER BY total DESC
    `);

    // ── Ingresos por día (últimos 30 días, combinados) ───────────
    const tendenciaRes = await pool.query(`
      SELECT fecha, SUM(total)::float AS total
      FROM (
        SELECT DATE(fecha_creacion) AS fecha, total
        FROM pedidos
        WHERE estado IN ('confirmado','entregado')
          AND fecha_creacion >= NOW() - INTERVAL '30 days'
        UNION ALL
        SELECT DATE(fecha_creacion) AS fecha, total
        FROM ventas_tienda
        WHERE estado = 'completada'
          AND fecha_creacion >= NOW() - INTERVAL '30 days'
      ) t
      GROUP BY fecha
      ORDER BY fecha ASC
    `);

    const posData    = posRes.rows[0]    || {};
    const posHoyData = posHoyRes.rows[0] || {};
    const onlineHoy  = onlineHoyRes.rows[0] || {};
    const online     = totalesRes.rows[0] || {};

    const ingresos_totales_combinados =
      (parseFloat(online.ingresos_totales) || 0) +
      (parseFloat(posData.ingresos_pos)    || 0);

    res.json({
      // ── Compatibilidad con el frontend anterior ──────────────
      totales: {
        total_pedidos:    (online.total_pedidos    || 0) + (posData.completadas_pos || 0),
        ingresos_totales: ingresos_totales_combinados,
        pendientes:       online.pendientes  || 0,
        entregados:       online.entregados  || 0,
      },
      masVendido:   masRes.rows[0]   || null,
      menosVendido: menosRes.rows[0] || null,

      // ── Datos nuevos para el frontend coordinado ─────────────
      online: {
        total_pedidos:   online.total_pedidos   || 0,
        ingresos:        online.ingresos_totales || 0,
        pendientes:      online.pendientes       || 0,
        entregados:      online.entregados       || 0,
        ingresos_hoy:    onlineHoy.ingresos_hoy_online || 0,
        pedidos_hoy:     onlineHoy.pedidos_hoy   || 0,
      },
      pos: {
        total_ventas:    posData.total_ventas_pos    || 0,
        completadas:     posData.completadas_pos      || 0,
        anuladas:        posData.anuladas_pos          || 0,
        ingresos:        posData.ingresos_pos          || 0,
        efectivo:        posData.pos_efectivo          || 0,
        tarjeta:         posData.pos_tarjeta           || 0,
        transferencia:   posData.pos_transferencia     || 0,
        ingresos_hoy:    posHoyData.ingresos_hoy       || 0,
        ventas_hoy:      posHoyData.ventas_hoy         || 0,
        efectivo_hoy:    posHoyData.efectivo_hoy       || 0,
        tarjeta_hoy:     posHoyData.tarjeta_hoy        || 0,
        transferencia_hoy: posHoyData.transferencia_hoy || 0,
      },
      combinado: {
        ingresos_totales: ingresos_totales_combinados,
        ingresos_hoy:
          (onlineHoy.ingresos_hoy_online || 0) +
          (posHoyData.ingresos_hoy       || 0),
        transacciones_totales:
          (online.total_pedidos    || 0) +
          (posData.completadas_pos || 0),
      },
      top5Productos: top5Res.rows,
      metodosPago:   metodosPagosRes.rows,
      tendencia30d:  tendenciaRes.rows,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── ENTRADAS DE INVENTARIO ──────────────────────────────────────

// GET /api/admin/entradas → historial completo
app.get("/api/admin/entradas", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        e.id,
        e.producto_id,
        p.nombre                                                        AS producto_nombre,
        p.precio::float                                                 AS precio_venta,
        e.cantidad,
        e.precio_compra::float,
        COALESCE(e.proveedor, '')                                       AS proveedor,
        COALESCE(e.factura,   '')                                       AS factura,
        COALESCE(e.notas,     '')                                       AS notas,
        e.fecha,
        e.fecha_creacion,
        ROUND(
          ((p.precio - e.precio_compra) / NULLIF(p.precio, 0)) * 100, 1
        )::float                                                        AS margen_pct
      FROM entradas_inventario e
      JOIN productos p ON p.id = e.producto_id
      ORDER BY e.fecha_creacion DESC
    `);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/admin/entradas/:id → una entrada específica
app.get("/api/admin/entradas/:id", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT e.*, p.nombre AS producto_nombre, p.precio::float AS precio_venta
      FROM entradas_inventario e
      JOIN productos p ON p.id = e.producto_id
      WHERE e.id = $1
    `, [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: "Entrada no encontrada" });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/admin/entradas/:id → editar entrada y ajustar stock atómicamente
app.put("/api/admin/entradas/:id", authMiddleware, async (req, res) => {
  const { cantidad, precio_compra, fecha, proveedor, factura, notas } = req.body;

  if (!cantidad || parseInt(cantidad) < 1)
    return res.status(400).json({ error: "La cantidad debe ser mayor a 0" });
  if (!precio_compra || parseFloat(precio_compra) <= 0)
    return res.status(400).json({ error: "precio_compra debe ser mayor a 0" });
  if (!fecha)
    return res.status(400).json({ error: "La fecha es requerida" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const orig = await client.query(
      "SELECT producto_id, cantidad FROM entradas_inventario WHERE id = $1",
      [req.params.id]
    );
    if (!orig.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Entrada no encontrada" });
    }

    const { producto_id, cantidad: cantidadOriginal } = orig.rows[0];
    const diff = parseInt(cantidad) - parseInt(cantidadOriginal);

    await client.query(`
      UPDATE entradas_inventario
      SET cantidad=$1, precio_compra=$2, fecha=$3, proveedor=$4, factura=$5, notas=$6
      WHERE id=$7
    `, [
      parseInt(cantidad),
      parseFloat(precio_compra),
      fecha,
      proveedor || null,
      factura   || null,
      notas     || null,
      req.params.id
    ]);

    let stockNuevo = null;
    if (diff !== 0) {
      const stockRes = await client.query(
        "UPDATE productos SET stock = GREATEST(stock + $1, 0) WHERE id = $2 RETURNING stock",
        [diff, producto_id]
      );
      stockNuevo = stockRes.rows[0]?.stock;
    } else {
      const stockRes = await client.query("SELECT stock FROM productos WHERE id = $1", [producto_id]);
      stockNuevo = stockRes.rows[0]?.stock;
    }

    await client.query("COMMIT");
    res.json({ ok: true, stock_nuevo: stockNuevo });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// POST /api/admin/entradas → registrar entrada y actualizar stock atómicamente
app.post("/api/admin/entradas", authMiddleware, async (req, res) => {
  const { producto_id, cantidad, precio_compra, fecha, proveedor, factura, notas } = req.body;
  const usuario_id = req.user.id;

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

    const prodRes = await client.query(
      "SELECT id, nombre, stock FROM productos WHERE id = $1", [producto_id]
    );
    if (!prodRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Producto no encontrado" });
    }

    const entrada = await client.query(`
      INSERT INTO entradas_inventario
        (producto_id, usuario_id, cantidad, precio_compra, fecha, proveedor, factura, notas)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `, [
      producto_id,
      usuario_id,
      parseInt(cantidad),
      parseFloat(precio_compra),
      fecha,
      proveedor || null,
      factura   || null,
      notas     || null
    ]);

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

// DELETE /api/admin/entradas/:id → eliminar entrada y revertir stock
app.delete("/api/admin/entradas/:id", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const entRes = await client.query(
      "SELECT producto_id, cantidad FROM entradas_inventario WHERE id = $1",
      [req.params.id]
    );
    if (!entRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Entrada no encontrada" });
    }

    const { producto_id, cantidad } = entRes.rows[0];

    await client.query(
      "UPDATE productos SET stock = GREATEST(stock - $1, 0) WHERE id = $2",
      [cantidad, producto_id]
    );

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

// ══════════════════════════════════════════════════════════════
//  PUNTO DE VENTA (POS) — VENTA EN TIENDA FÍSICA
// ══════════════════════════════════════════════════════════════

// Generar número de factura único: DI-YYYYMMDD-XXXXX
async function generarNumFactura(client) {
  const hoy = new Date();
  const fecha = hoy.getFullYear().toString()
    + String(hoy.getMonth()+1).padStart(2,"0")
    + String(hoy.getDate()).padStart(2,"0");
  const res = await client.query(
    `SELECT COUNT(*) FROM ventas_tienda
     WHERE numero_factura LIKE $1`,
    [`DI-${fecha}-%`]
  );
  const seq = String(parseInt(res.rows[0].count) + 1).padStart(4,"0");
  return `DI-${fecha}-${seq}`;
}

// GET /api/admin/pos/productos → catálogo activo con stock para la caja POS
app.get("/api/admin/pos/productos", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, nombre, descripcion, precio::float, stock, imagen, estado
      FROM productos
      WHERE estado = 'activo'
      ORDER BY nombre ASC
    `);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/admin/pos/resumen-hoy → KPIs de caja del día actual
app.get("/api/admin/pos/resumen-hoy", authMiddleware, async (req, res) => {
  try {
    const hoy = new Date().toISOString().slice(0,10); // YYYY-MM-DD
    const r = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE estado='completada')::int          AS ventas_hoy,
        COALESCE(SUM(total) FILTER (WHERE estado='completada'),0)::float AS ingresos_hoy,
        COUNT(*) FILTER (WHERE estado='anulada')::int             AS anuladas_hoy,
        COALESCE(SUM(total) FILTER (WHERE metodo_pago='Efectivo' AND estado='completada'),0)::float AS efectivo_hoy,
        COALESCE(SUM(total) FILTER (WHERE metodo_pago='Tarjeta'  AND estado='completada'),0)::float AS tarjeta_hoy,
        COALESCE(SUM(total) FILTER (WHERE metodo_pago='Transferencia' AND estado='completada'),0)::float AS transferencia_hoy,
        COUNT(DISTINCT DATE(fecha_creacion))::int                 AS dias_con_ventas
      FROM ventas_tienda
      WHERE DATE(fecha_creacion) = $1
    `, [hoy]);

    // Top 5 productos vendidos hoy
    const top = await pool.query(`
      SELECT dvt.nombre_producto, SUM(dvt.cantidad)::int AS qty,
             SUM(dvt.subtotal)::float AS total
      FROM detalle_venta_tienda dvt
      JOIN ventas_tienda vt ON vt.id = dvt.venta_id
      WHERE DATE(vt.fecha_creacion) = $1 AND vt.estado = 'completada'
      GROUP BY dvt.nombre_producto
      ORDER BY qty DESC LIMIT 5
    `, [hoy]);

    res.json({ ...r.rows[0], top_productos: top.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/admin/pos/ventas → historial con filtros opcionales
app.get("/api/admin/pos/ventas", authMiddleware, async (req, res) => {
  const { desde, hasta, estado, metodo } = req.query;
  try {
    let where = ["1=1"];
    const params = [];
    if (desde)  { params.push(desde);  where.push(`DATE(vt.fecha_creacion) >= $${params.length}`); }
    if (hasta)  { params.push(hasta);  where.push(`DATE(vt.fecha_creacion) <= $${params.length}`); }
    if (estado) { params.push(estado); where.push(`vt.estado = $${params.length}`); }
    if (metodo) { params.push(metodo); where.push(`vt.metodo_pago = $${params.length}`); }

    const ventas = await pool.query(`
      SELECT vt.*,
             vt.subtotal::float,
             vt.descuento_pct::float,
             vt.descuento_monto::float,
             vt.itbis::float,
             vt.total::float,
             vt.monto_recibido::float,
             vt.cambio::float,
             u.nombre AS cajero
      FROM ventas_tienda vt
      LEFT JOIN usuarios u ON u.id = vt.usuario_id
      WHERE ${where.join(" AND ")}
      ORDER BY vt.fecha_creacion DESC
    `, params);

    if (!ventas.rows.length) return res.json([]);

    const ids = ventas.rows.map(v => v.id);
    const detalles = await pool.query(`
      SELECT venta_id, nombre_producto, precio_unitario::float,
             cantidad, subtotal::float, producto_id
      FROM detalle_venta_tienda
      WHERE venta_id = ANY($1)
    `, [ids]);

    const detMap = {};
    for (const d of detalles.rows) {
      if (!detMap[d.venta_id]) detMap[d.venta_id] = [];
      detMap[d.venta_id].push(d);
    }

    res.json(ventas.rows.map(v => ({ ...v, items: detMap[v.id] || [] })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/admin/pos/ventas/:id → factura individual
app.get("/api/admin/pos/ventas/:id", authMiddleware, async (req, res) => {
  try {
    const venta = await pool.query(`
      SELECT vt.*, vt.subtotal::float, vt.descuento_pct::float,
             vt.descuento_monto::float, vt.itbis::float,
             vt.total::float, vt.monto_recibido::float, vt.cambio::float,
             u.nombre AS cajero
      FROM ventas_tienda vt
      LEFT JOIN usuarios u ON u.id = vt.usuario_id
      WHERE vt.id = $1
    `, [req.params.id]);
    if (!venta.rows.length) return res.status(404).json({ error: "Venta no encontrada" });

    const items = await pool.query(`
      SELECT nombre_producto, precio_unitario::float, cantidad, subtotal::float
      FROM detalle_venta_tienda WHERE venta_id = $1
    `, [req.params.id]);

    res.json({ ...venta.rows[0], items: items.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/admin/pos/venta → registrar nueva venta en tienda
app.post("/api/admin/pos/venta", authMiddleware, async (req, res) => {
  const {
    items, cliente_nombre, metodo_pago,
    descuento_pct, itbis_pct,
    monto_recibido, notas
  } = req.body;

  if (!Array.isArray(items) || items.length === 0)
    return res.status(400).json({ error: "La venta debe tener al menos un producto" });
  if (!metodo_pago)
    return res.status(400).json({ error: "metodo_pago es requerido" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Verificar stock y bloquear filas
    for (const item of items) {
      if (!item.producto_id) continue;
      const prod = await client.query(
        "SELECT stock, nombre FROM productos WHERE id=$1 FOR UPDATE",
        [item.producto_id]
      );
      if (!prod.rows.length) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: `Producto ID ${item.producto_id} no encontrado` });
      }
      const { stock, nombre } = prod.rows[0];
      if (stock < item.cantidad) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          error: `Stock insuficiente para "${nombre}". Disponible: ${stock}, solicitado: ${item.cantidad}`
        });
      }
    }

    // Calcular totales
    const descPct  = parseFloat(descuento_pct  || 0);
    const itbisPct = parseFloat(itbis_pct || 0);
    const subtotalBruto = items.reduce((s, i) => s + (parseFloat(i.precio_unitario) * parseInt(i.cantidad)), 0);
    const descMonto     = parseFloat((subtotalBruto * descPct / 100).toFixed(2));
    const subtotal      = parseFloat((subtotalBruto - descMonto).toFixed(2));
    const itbisMonto    = parseFloat((subtotal * itbisPct / 100).toFixed(2));
    const total         = parseFloat((subtotal + itbisMonto).toFixed(2));
    const cambio        = monto_recibido ? parseFloat((parseFloat(monto_recibido) - total).toFixed(2)) : null;

    // Número de factura
    const numero_factura = await generarNumFactura(client);

    // Insertar cabecera
    const ventaRes = await client.query(`
      INSERT INTO ventas_tienda
        (numero_factura, usuario_id, cliente_nombre, subtotal, descuento_pct,
         descuento_monto, itbis, total, metodo_pago, monto_recibido, cambio, notas)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      RETURNING *
    `, [
      numero_factura,
      req.user.id,
      cliente_nombre || null,
      subtotal,
      descPct,
      descMonto,
      itbisMonto,
      total,
      metodo_pago,
      monto_recibido ? parseFloat(monto_recibido) : null,
      cambio,
      notas || null
    ]);

    const ventaId = ventaRes.rows[0].id;

    // Insertar detalles + descontar stock
    for (const item of items) {
      const linSub = parseFloat((parseFloat(item.precio_unitario) * parseInt(item.cantidad)).toFixed(2));
      await client.query(`
        INSERT INTO detalle_venta_tienda
          (venta_id, producto_id, nombre_producto, precio_unitario, cantidad, subtotal)
        VALUES ($1,$2,$3,$4,$5,$6)
      `, [ventaId, item.producto_id || null, item.nombre_producto, parseFloat(item.precio_unitario), parseInt(item.cantidad), linSub]);

      if (item.producto_id) {
        await client.query(
          "UPDATE productos SET stock = GREATEST(stock - $1, 0) WHERE id=$2",
          [parseInt(item.cantidad), item.producto_id]
        );
      }
    }

    await client.query("COMMIT");
    res.status(201).json({
      ok: true,
      venta_id: ventaId,
      numero_factura,
      total,
      cambio
    });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// PUT /api/admin/pos/ventas/:id/anular → anular venta y reponer stock
app.put("/api/admin/pos/ventas/:id/anular", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const venta = await client.query(
      "SELECT estado FROM ventas_tienda WHERE id=$1", [req.params.id]
    );
    if (!venta.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Venta no encontrada" });
    }
    if (venta.rows[0].estado === "anulada") {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "La venta ya está anulada" });
    }

    // Reponer stock
    const items = await client.query(
      "SELECT producto_id, cantidad FROM detalle_venta_tienda WHERE venta_id=$1 AND producto_id IS NOT NULL",
      [req.params.id]
    );
    for (const row of items.rows) {
      await client.query(
        "UPDATE productos SET stock = stock + $1 WHERE id=$2",
        [row.cantidad, row.producto_id]
      );
    }

    await client.query(
      "UPDATE ventas_tienda SET estado='anulada' WHERE id=$1", [req.params.id]
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

// ── KEEP-ALIVE (evita que Render se duerma en plan gratuito) ────
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
}).catch(err => {
  console.error("❌ Error al iniciar el servidor:", err.message);
  process.exit(1);
});
