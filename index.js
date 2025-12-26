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
const dbUrl = "mongodb+srv://andukamarlony_db_user:4QMlMiSbaVgGOI0v@cluster0.m4tjofp.mongodb.net/"

// CORS - Allow all origins explicitly
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*')
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization')
  res.header('Access-Control-Expose-Headers', 'Authorization')
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200)
  }
  next()
})

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
    // Add connection options for better error handling
    await mongoose.connect(dbUrl, {
      serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
      retryWrites: true,
    })
    dbConnected = true
    console.log('[db] connected successfully')
    return true
  } catch (err) {
    console.error('[db] connection error:', err.message)
    
    // Provide helpful error messages
    if (err.message.includes('Authentication failed') || err.code === 8000) {
      console.error('[db] AUTH ERROR: Check your MongoDB credentials:')
      console.error('  1. Verify username and password in DATABASE_URL')
      console.error('  2. URL-encode special characters in password (!@#$%^&* etc.)')
      console.error('  3. Check MongoDB Atlas Network Access - whitelist your IP (0.0.0.0/0 for all)')
      console.error('  4. Verify database user has correct permissions')
    } else if (err.message.includes('ENOTFOUND') || err.message.includes('getaddrinfo')) {
      console.error('[db] NETWORK ERROR: Cannot reach MongoDB server')
      console.error('  Check your DATABASE_URL hostname')
    } else {
      console.error('[db] Connection failed:', err.message)
    }
    
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

const paymentSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    plan: { type: String, required: true },
    amount: { type: Number, required: true },
    currency: { type: String, default: 'USD' },
    phone: { type: String, required: true },
    provider: { type: String },
    depositId: { type: String }, // PawaPay deposit ID
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
    paidAt: { type: Date },
    reference: { type: String },
  },
  { timestamps: true }
)

const User = mongoose.model('User', userSchema)
const Cv = mongoose.model('Cv', cvSchema)
const Payment = mongoose.model('Payment', paymentSchema)

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

// Check if user has paid for the plan
async function hasPaidForPlan(userId, plan) {
  const payment = await Payment.findOne({
    userId,
    plan,
    status: 'completed'
  }).lean()
  return !!payment
}

app.post('/api/cv', auth, async (req, res) => {
  const { id, data, withPhoto, plan, title } = req.body || {}
  if (!data) return res.status(400).json({ error: 'CV data is required' })
  
  // Check if user has paid for this plan (only for new CVs)
  if (!id) {
    const paid = await hasPaidForPlan(req.user.sub, plan || 'student')
    if (!paid) {
      return res.status(402).json({ 
        error: 'Payment required', 
        message: 'You must complete payment before creating a CV',
        requiresPayment: true 
      })
    }
  }
  
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

// PawaPay API configuration
const PAWAPAY_API_TOKEN = "eyJraWQiOiIxIiwiYWxnIjoiRVMyNTYifQ.eyJ0dCI6IkFBVCIsInN1YiI6IjE4NzUiLCJtYXYiOiIxIiwiZXhwIjoyMDgyMjkzMzU3LCJpYXQiOjE3NjY3NjA1NTcsInBtIjoiREFGLFBBRiIsImp0aSI6IjhjZmVhMWIwLWU1YzctNGQ3Mi1iYzVmLWRmMTNmYTVmMWU5MCJ9.OINT4nV0qzCQ6_iTXxybOEf_uGyhyt-cphbmSRYsI66OPP5vHI_UCmqw2CuJuMvJQmpdnU3DN0-R4XPc53Z2Fg"
const PAWAPAY_API_URL = "https://api.sandbox.pawapay.io" // Use sandbox for testing

// Create payment request
app.post('/api/payments/create', auth, async (req, res) => {
  const { plan, amount, phone, provider } = req.body || {}
  
  if (!plan || !amount || !phone) {
    return res.status(400).json({ error: 'Plan, amount, and phone are required' })
  }

  try {
    // Create payment record
    const payment = await Payment.create({
      userId: req.user.sub,
      plan,
      amount,
      currency: 'USD',
      phone,
      provider: provider || 'mtn',
      status: 'pending'
    })

    // Normalize phone number to MSISDN format (remove spaces, ensure + prefix)
    let normalizedPhone = phone.replace(/\s+/g, '').trim()
    if (!normalizedPhone.startsWith('+')) {
      normalizedPhone = '+' + normalizedPhone
    }
    
    // Prepare PawaPay request payload
    const pawapayPayload = {
      amount: {
        amount: amount.toString(),
        currency: 'USD'
      },
      customer: {
        phoneNumber: normalizedPhone
      },
      merchantReference: payment._id.toString(),
      callbackUrl: `${process.env.BACKEND_URL || 'https://backend-topaz-nine-29.vercel.app'}/api/payments/callback`,
      returnUrl: `${process.env.FRONTEND_URL || 'https://ethane-chi.vercel.app'}/?payment=success&depositId={depositId}`
    }
    
    // Add email if available
    if (req.user.email) {
      pawapayPayload.customer.email = req.user.email
    }
    
    // Log request details (without full token for security)
    console.log('[PawaPay] Request:', {
      url: `${PAWAPAY_API_URL}/deposits`,
      payload: pawapayPayload,
      tokenPrefix: PAWAPAY_API_TOKEN.substring(0, 20) + '...',
      tokenLength: PAWAPAY_API_TOKEN.length
    })
    
    // Call PawaPay API to create payment
    // Note: Make sure the token is valid and has proper permissions in PawaPay dashboard
    const pawapayResponse = await fetch(`${PAWAPAY_API_URL}/deposits`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${PAWAPAY_API_TOKEN}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(pawapayPayload)
    })
    
    // Log response status immediately
    console.log('[PawaPay] Response Status:', pawapayResponse.status, pawapayResponse.statusText)

    if (!pawapayResponse.ok) {
      let errorData = {}
      let errorText = ''
      try {
        errorText = await pawapayResponse.text()
        errorData = JSON.parse(errorText)
      } catch (e) {
        errorData = { error: errorText || 'Unknown error' }
      }
      
      console.error('[PawaPay] Error Response:', {
        status: pawapayResponse.status,
        statusText: pawapayResponse.statusText,
        errorData,
        errorText,
        url: `${PAWAPAY_API_URL}/deposits`,
        headers: Object.fromEntries(pawapayResponse.headers.entries())
      })
      
      await Payment.findByIdAndUpdate(payment._id, { status: 'failed' })
      
      const errorMessage = errorData.failureReason?.failureMessage || 
                          errorData.errorMessage || 
                          errorData.error || 
                          'PawaPay API error'
      
      return res.status(pawapayResponse.status || 500).json({ 
        error: 'Payment initiation failed', 
        details: errorData,
        message: errorMessage
      })
    }

    const pawapayData = await pawapayResponse.json()
    
    // Update payment with deposit ID
    await Payment.findByIdAndUpdate(payment._id, {
      depositId: pawapayData.depositId,
      reference: pawapayData.merchantReference
    })

    return res.json({
      paymentId: payment._id,
      depositId: pawapayData.depositId,
      redirectUrl: pawapayData.redirectUrl || pawapayData.paymentUrl,
      status: 'pending'
    })
  } catch (err) {
    console.error('[Payment] Error:', err)
    return res.status(500).json({ error: 'Payment creation failed', message: err.message })
  }
})

// Verify payment status
app.get('/api/payments/status/:depositId', auth, async (req, res) => {
  const { depositId } = req.params
  
  try {
    // Check PawaPay API for payment status
    const pawapayResponse = await fetch(`${PAWAPAY_API_URL}/deposits/${depositId}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${PAWAPAY_API_TOKEN}`,
        'Content-Type': 'application/json'
      }
    })

    if (!pawapayResponse.ok) {
      return res.status(404).json({ error: 'Payment not found' })
    }

    const pawapayData = await pawapayResponse.json()
    
    // Update payment status in database
    const payment = await Payment.findOneAndUpdate(
      { depositId, userId: req.user.sub },
      {
        status: pawapayData.status === 'COMPLETED' ? 'completed' : 
                pawapayData.status === 'FAILED' ? 'failed' : 'pending',
        paidAt: pawapayData.status === 'COMPLETED' ? new Date() : undefined
      },
      { new: true }
    )

    if (!payment) {
      return res.status(404).json({ error: 'Payment record not found' })
    }

    return res.json({
      paymentId: payment._id,
      depositId: payment.depositId,
      status: payment.status,
      plan: payment.plan,
      amount: payment.amount,
      paidAt: payment.paidAt
    })
  } catch (err) {
    console.error('[Payment Status] Error:', err)
    return res.status(500).json({ error: 'Failed to check payment status', message: err.message })
  }
})

// PawaPay webhook callback
app.post('/api/payments/callback', async (req, res) => {
  const { depositId, status, merchantReference } = req.body || {}
  
  try {
    const payment = await Payment.findById(merchantReference)
    if (!payment) {
      return res.status(404).json({ error: 'Payment not found' })
    }

    const paymentStatus = status === 'COMPLETED' ? 'completed' : 
                         status === 'FAILED' ? 'failed' : 'pending'
    
    await Payment.findByIdAndUpdate(payment._id, {
      status: paymentStatus,
      paidAt: paymentStatus === 'completed' ? new Date() : undefined
    })

    return res.json({ success: true })
  } catch (err) {
    console.error('[Payment Callback] Error:', err)
    return res.status(500).json({ error: 'Callback processing failed' })
  }
})

// Check if user has paid
app.get('/api/payments/check/:plan', auth, async (req, res) => {
  const { plan } = req.params
  const paid = await hasPaidForPlan(req.user.sub, plan)
  return res.json({ paid })
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
