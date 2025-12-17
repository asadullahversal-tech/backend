const express = require('express')
const cors = require('cors')
const dotenv = require('dotenv')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const mongoose = require('mongoose')

dotenv.config()

const app = express()
const port = process.env.PORT || 8080
const jwtSecret = process.env.JWT_SECRET || process.env.ACCESS_TOKEN_SECRET || 'change-me'
const dbUrl = process.env.DATABASE_URL

const corsOptions = {
  origin: true, // Allow all origins
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}

app.use(cors(corsOptions))
app.options('*', cors(corsOptions))
app.use(express.json())

// --- DB connection ---
let dbConnected = false

async function connectDb() {
  if (!dbUrl) {
    console.warn('[db] DATABASE_URL is missing; API will fail without a DB.')
    return false
  }
  
  // Reuse existing connection if available
  if (mongoose.connection.readyState === 1) {
    return true
  }
  
  try {
    await mongoose.connect(dbUrl)
    dbConnected = true
    console.log('[db] connected')
    return true
  } catch (err) {
    console.error('[db] connection error', err)
    dbConnected = false
    return false
  }
}

// Connect to DB on startup (non-blocking)
connectDb().catch(err => {
  console.error('[db] Initial connection failed:', err)
})

// --- Schemas ---
const userSchema = new mongoose.Schema(
  {
    phone: { type: String, unique: true, required: true },
    name: { type: String },
    password: { type: String, required: true },
  },
  { timestamps: true }
)

const cvSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    data: { type: mongoose.Schema.Types.Mixed, required: true },
    withPhoto: { type: Boolean, default: false },
    plan: { type: String, default: 'student' },
    title: { type: String, default: 'CV' },
  },
  { timestamps: true }
)

const User = mongoose.model('User', userSchema)
const Cv = mongoose.model('Cv', cvSchema)

// --- Helpers ---
function normalizePhone(phone) {
  if (!phone) return ''
  // Remove spaces and dashes, keep leading + if present
  const trimmed = phone.trim()
  const hasPlus = trimmed.startsWith('+')
  const digits = trimmed.replace(/[^\d]/g, '')
  return hasPlus ? `+${digits}` : digits
}

function signToken(user) {
  return jwt.sign({ sub: user._id.toString(), phone: user.phone }, jwtSecret, { expiresIn: '7d' })
}

async function auth(req, res, next) {
  const header = req.headers.authorization || ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : null
  if (!token) return res.status(401).json({ error: 'Missing token' })
  try {
    const payload = jwt.verify(token, jwtSecret)
    req.user = payload
    next()
  } catch {
    return res.status(401).json({ error: 'Invalid token' })
  }
}

// Health check endpoint (before DB middleware)
app.get('/api/health', (_req, res) => {
  res.json({ 
    status: 'ok', 
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString()
  })
})

// Middleware to ensure DB connection before handling requests (except health check)
app.use(async (req, res, next) => {
  // Skip DB check for health check and root endpoint
  if (req.path === '/' || req.path === '/api/health') {
    return next()
  }
  
  // Try to connect if not connected
  if (!dbConnected && mongoose.connection.readyState !== 1) {
    const connected = await connectDb()
    if (!connected && dbUrl) {
      return res.status(503).json({ error: 'Database connection unavailable' })
    }
  }
  next()
})

// --- Routes ---
app.get('/', (_req, res) => {
  res.send('API is live')
})

app.post('/api/auth/signup', async (req, res) => {
  const { phone, password, name } = req.body || {}
  if (!phone || !password || password.length < 6) {
    return res.status(400).json({ error: 'Phone number and password (>=6 chars) are required.' })
  }
  const normalizedPhone = normalizePhone(phone)
  const exists = await User.findOne({ phone: normalizedPhone }).lean()
  if (exists) return res.status(409).json({ error: 'User already exists' })
  const hash = await bcrypt.hash(password, 10)
  try {
    const user = await User.create({
      phone: normalizedPhone,
      name: name || normalizedPhone,
      password: hash,
    })
    const token = signToken(user)
    return res.json({ token, user: { id: user._id, phone: user.phone, name: user.name } })
  } catch (err) {
    if (err?.code === 11000) {
      return res.status(409).json({ error: 'User already exists' })
    }
    console.error('[signup] error', err)
    return res.status(500).json({ error: 'Signup failed' })
  }
})

app.post('/api/auth/login', async (req, res) => {
  const { phone, password } = req.body || {}
  if (!phone || !password) return res.status(400).json({ error: 'Phone number and password are required.' })
  const normalizedPhone = normalizePhone(phone)
  const user = await User.findOne({ phone: normalizedPhone })
  if (!user) return res.status(401).json({ error: 'Invalid phone or password' })
  const ok = await bcrypt.compare(password, user.password)
  if (!ok) return res.status(401).json({ error: 'Invalid phone or password' })
  const token = signToken(user)
  return res.json({ token, user: { id: user._id, phone: user.phone, name: user.name } })
})

app.get('/api/auth/me', auth, async (req, res) => {
  const user = await User.findById(req.user.sub).lean()
  if (!user) return res.status(404).json({ error: 'User not found' })
  return res.json({ user: { id: user._id, phone: user.phone, name: user.name } })
})

app.get('/api/cv', auth, async (req, res) => {
  const cvs = await Cv.find({ userId: req.user.sub }).sort({ updatedAt: -1 }).lean()
  return res.json({ cvs })
})

app.get('/api/cv/:id', auth, async (req, res) => {
  const cv = await Cv.findOne({ _id: req.params.id, userId: req.user.sub }).lean()
  if (!cv) return res.status(404).json({ error: 'Not found' })
  return res.json({ cv })
})

app.post('/api/cv', auth, async (req, res) => {
  const { id, data, withPhoto, plan, title } = req.body || {}
  if (!data) return res.status(400).json({ error: 'CV data is required' })
  let cv
  if (id) {
    cv = await Cv.findOneAndUpdate(
      { _id: id, userId: req.user.sub },
      { data, withPhoto: !!withPhoto, plan: plan || 'student', title: title || 'CV' },
      { new: true }
    )
  } else {
    cv = await Cv.create({
      userId: req.user.sub,
      data,
      withPhoto: !!withPhoto,
      plan: plan || 'student',
      title: title || (data.fullName || 'CV'),
    })
  }
  return res.json({ cv })
})

// ⚠️ Dev-only helper to clear all users (for local testing only)
if (process.env.NODE_ENV !== 'production') {
  app.post('/api/debug/clear-users', async (_req, res) => {
    try {
      await User.deleteMany({})
      return res.json({ ok: true })
    } catch (err) {
      console.error('[debug] clear-users error', err)
      return res.status(500).json({ error: 'Failed to clear users' })
    }
  })
}

// 404 handler
app.use((_req, res) => {
  res.status(404).send("Sorry can't find that!")
})

// Error handler
app.use((err, _req, res, _next) => {
  console.error(err.stack)
  res.status(500).json({ error: 'Internal server error', message: err.message })
})

// Export for Vercel serverless
module.exports = app
