const express = require('express')
const path = require('path')
const crypto = require('crypto')
const mysql = require('mysql2/promise')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { body, validationResult } = require('express-validator')

const app = express()
const port = 3000
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_with_strong_secret'
const API_KEY_TTL_DAYS = 30 // default expiry 30 hari

// DB config
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: '@21baplanGGG',
  database: 'api_key_db',
  port: 3309,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
}
const pool = mysql.createPool(dbConfig)

// test connection
async function testConnection() {
  try {
    const conn = await pool.getConnection()
    console.log('✅ Koneksi ke MySQL berhasil!')
    conn.release()
  } catch (err) {
    console.error('❌ Gagal koneksi ke MySQL:', err.message)
    process.exit(1)
  }
}
testConnection()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
//app.use(express.static('public'))
app.use(express.static(path.join(__dirname, 'public'), { index: false }))

/* ---------- Utility ---------- */
function genApiKey() {
  const timestamp = Date.now()
  const random = crypto.randomBytes(32).toString('base64url')
  return 'sk-itumy-v1-' + timestamp + '_' + random
}

function addDaysToNow(days) {
  const d = new Date()
  d.setDate(d.getDate() + days)
  return d
}

/* ---------- Middleware ---------- */
// verify admin JWT
async function verifyAdminToken(req, res, next) {
  try {
    const auth = req.headers.authorization
    if (!auth) return res.status(401).json({ success:false, message: 'Unauthorized' })
    const parts = auth.split(' ')
    if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ success:false, message: 'Invalid token format' })
    const token = parts[1]
    const payload = jwt.verify(token, JWT_SECRET)
    // attach admin id
    req.admin = { id: payload.id, email: payload.email }
    next()
  } catch (err) {
    return res.status(401).json({ success:false, message: 'Invalid or expired token', error: err.message })
  }
}

/* ---------- User-facing: register user & generate key ---------- */
/**
 * NOTE:
 * - UI will call POST /create-user to generate API key & save relationship user -> api_keys
 * - expiry default = now + API_KEY_TTL_DAYS
 */
app.post('/create-user', [
  body('firstName').trim().notEmpty(),
  body('lastName').trim().notEmpty(),
  body('email').isEmail()
], async (req, res) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) return res.status(400).json({ success:false, errors: errors.array() })
  const { firstName, lastName, email } = req.body
  let connection
  try {
    connection = await pool.getConnection()
    await connection.beginTransaction()

    // create api key record
    const apiKey = genApiKey()
    const expiry = addDaysToNow(API_KEY_TTL_DAYS) // out_of_date
    const [apiRes] = await connection.query(
      'INSERT INTO api_keys (api_key, out_of_date, is_active) VALUES (?, ?, ?)',
      [apiKey, expiry, 1]
    )
    const apiId = apiRes.insertId

    // create user and link
    const [userRes] = await connection.query(
      'INSERT INTO users (first_name, last_name, email, api_key_id, last_login) VALUES (?, ?, ?, ?, ?)',
      [firstName, lastName, email, apiId, new Date()]
    )

    await connection.commit()
    connection.release()

    res.json({
      success: true,
      message: 'User and API key created',
      data: {
        userId: userRes.insertId,
        apiKey: apiKey,
        out_of_date: expiry
      }
    })
  } catch (err) {
    if (connection) await connection.rollback().catch(()=>{})
    console.error('❌ Error create-user:', err)
    return res.status(500).json({ success:false, message: err.message })
  } finally {
    if (connection) connection && connection.release()
  }
})

/* ---------- Admin register ---------- */
/* ---------- Admin register (FIXED & COMPLETE) ---------- */
app.post('/admin/register', [
  body('email').isEmail(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) return res.status(400).json({ success:false, errors: errors.array() })

  const { email, password } = req.body
  let connection

  try {
    connection = await pool.getConnection()

    // cek apakah admin sudah ada
    const [exist] = await connection.query(
      'SELECT id FROM admins WHERE email = ?',
      [email]
    )
    if (exist.length > 0) {
      connection.release()
      return res.status(400).json({ success:false, message: 'Email admin sudah terdaftar' })
    }

    // hash password
    const hashed = await bcrypt.hash(password, 10)

    // insert admin baru
    const [ins] = await connection.query(
      'INSERT INTO admins (email, password_hash) VALUES (?, ?)',
      [email, hashed]
    )

    connection.release()

    return res.json({
      success: true,
      message: 'Admin berhasil didaftarkan',
      adminId: ins.insertId
    })
  } catch (err) {
    if (connection) connection.release()
    console.error('❌ Error admin register:', err)
    return res.status(500).json({ success:false, message: err.message })
  }
})



/* ---------- Admin login (returns JWT) ---------- */
/* ---------- Admin login (pakai email) ---------- */
app.post('/admin/login', [
  body('email').isEmail(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req)
  if (!errors.isEmpty()) return res.status(400).json({ success:false, errors: errors.array() })

  const { email, password } = req.body
  let connection
  try {
    connection = await pool.getConnection()

    const [rows] = await connection.query('SELECT * FROM admins WHERE email = ?', [email])
    if (rows.length === 0) {
      connection.release()
      return res.status(401).json({ success:false, message: 'Email tidak ditemukan' })
    }

    const admin = rows[0]
    const ok = await bcrypt.compare(password, admin.password_hash)
    if (!ok) {
      connection.release()
      return res.status(401).json({ success:false, message: 'Password salah' })
    }

    const token = jwt.sign(
      { id: admin.id, email: admin.email },
      JWT_SECRET,
      { expiresIn: '8h' }
    )

    connection.release()

    res.json({
      success: true,
      message: 'Login berhasil',
      token
    })
  } catch (err) {
    if (connection) connection.release()
    console.error('❌ Error admin login:', err)
    res.status(500).json({ success:false, message: err.message })
  }
})


/* ---------- Admin: dashboard (protected) ----------
   Returns list of users with api key and status.
   Also automatically deactivates keys that are expired (out_of_date < now)
   and deactivates keys where user's last_login > 30 days (business rule).
*/
app.get('/admin/dashboard', verifyAdminToken, async (req, res) => {
  let connection
  try {
    connection = await pool.getConnection()
    // 1) Deactivate expired keys (out_of_date < now)
    await connection.query('UPDATE api_keys SET is_active = 0 WHERE out_of_date < NOW() AND is_active = 1')

    // 2) Deactivate keys where user.last_login older than 30 days
    await connection.query(
      `UPDATE api_keys a
       JOIN users u ON u.api_key_id = a.id
       SET a.is_active = 0
       WHERE (u.last_login IS NULL OR u.last_login < DATE_SUB(NOW(), INTERVAL 30 DAY))
         AND a.is_active = 1`
    )

    // 3) Select user + api key info
    const [rows] = await connection.query(
      `SELECT u.id AS user_id, u.first_name, u.last_name, u.email, u.last_login,
              a.api_key AS api_key, a.out_of_date, a.is_active
       FROM users u
       LEFT JOIN api_keys a ON u.api_key_id = a.id
       ORDER BY u.created_at DESC`
    )

    connection.release()
    // map to status label
    const mapped = rows.map(r => ({
      user_id: r.user_id,
      first_name: r.first_name,
      last_name: r.last_name,
      email: r.email,
      last_login: r.last_login,
      api_key: r.api_key,
      out_of_date: r.out_of_date,
      is_active: !!r.is_active,
      status: r.is_active ? 'active' : 'inactive'
    }))

    res.json({ success:true, total: mapped.length, users: mapped })
  } catch (err) {
    if (connection) connection.release()
    console.error('❌ Error dashboard:', err)
    res.status(500).json({ success:false, message: err.message })
  }
})

/* ---------- Admin: delete user (per-row delete) ---------- */
app.delete('/admin/user/:id', verifyAdminToken, async (req, res) => {
  const userId = parseInt(req.params.id, 10)
  let connection
  try {
    connection = await pool.getConnection()
    const [del] = await connection.query('DELETE FROM users WHERE id = ?', [userId])
    connection.release()
    if (del.affectedRows > 0) {
      return res.json({ success:true, message: 'User deleted' })
    } else {
      return res.status(404).json({ success:false, message: 'User not found' })
    }
  } catch (err) {
    if (connection) connection.release()
    console.error('❌ Error delete user:', err)
    res.status(500).json({ success:false, message: err.message })
  }
})

/* ---------- Endpoint for checking API Key (unchanged logic, but updated to join user) ---------- */
app.post('/checkapi', async (req, res) => {
  let connection;
  try {
    const { apiKey } = req.body
    if (!apiKey) {
      return res.status(400).json({ success:false, message: 'API Key tidak boleh kosong', valid: false })
    }
    connection = await pool.getConnection()
    const [rows] = await connection.query(
      `SELECT a.*, u.id as user_id, u.first_name, u.email
       FROM api_keys a
       LEFT JOIN users u ON u.api_key_id = a.id
       WHERE a.api_key = ? AND a.is_active = 1`,
      [apiKey]
    )
    if (rows.length > 0) {
      const keyData = rows[0]
      // optionally update user's last_login when they use the key (helps "1 bulan" rule)
      if (keyData.user_id) {
        await connection.query('UPDATE users SET last_login = ? WHERE id = ?', [new Date(), keyData.user_id])
      }
      connection.release()
      return res.json({
        success:true,
        valid:true,
        message: 'API Key valid',
        data: {
          id: keyData.id,
          apiKey: keyData.api_key,
          out_of_date: keyData.out_of_date,
          status: keyData.is_active ? 'active' : 'inactive',
          user: keyData.user_id ? { id: keyData.user_id, first_name: keyData.first_name, email: keyData.email } : null
        }
      })
    } else {
      connection.release()
      return res.status(401).json({ success:false, valid: false, message: 'API Key tidak valid atau tidak aktif' })
    }
  } catch (err) {
    if (connection) connection.release()
    console.error('❌ Error check API key:', err)
    res.status(500).json({ success:false, message: err.message })
  }
})

/* ---------- Serve root ---------- */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'landing.html'))
})

process.on('SIGTERM', async () => {
  console.log('SIGTERM signal received: closing HTTP server')
  await pool.end()
  process.exit(0)
})

app.listen(port, () => {
  console.log(`🚀 Server berjalan di http://localhost:${port}`)
})
