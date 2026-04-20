const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

const app = express();

app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

const allowedOrigins = [
  'https://aporialab.space',
  'https://www.aporialab.space',
  'https://aporialab-frontend.vercel.app',
  'http://localhost:5173',
  'http://localhost:3000',
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (origin.endsWith('.vercel.app')) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: false
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { success: false, message: 'الكثير من الطلبات. حاول مرة أخرى بعد 15 دقيقة.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { success: false, message: 'الكثير من محاولات تسجيل الدخول. حاول بعد 15 دقيقة.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});

app.use('/api/', generalLimiter);

const JWT_SECRET = process.env.JWT_SECRET || 'aporialab-secret-key-2026';
const MONGODB_URI = process.env.MONGODB_URI;

let cachedConnection = null;
async function connectDB() {
  if (cachedConnection && mongoose.connection.readyState === 1) return cachedConnection;
  if (!MONGODB_URI) throw new Error('MONGODB_URI not configured');
  try {
    cachedConnection = await mongoose.connect(MONGODB_URI, {
      bufferCommands: false,
      serverSelectionTimeoutMS: 10000,
    });
    return cachedConnection;
  } catch (error) {
    console.error('MongoDB connection error:', error.message);
    cachedConnection = null;
    throw error;
  }
}

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 200 },
  password: { type: String, required: true },
  avatar: { type: String, default: '' },
  bio: { type: String, default: '', maxlength: 500 },
  reputation: { type: Number, default: 0 },
  role: { type: String, enum: ['user', 'moderator', 'admin'], default: 'user' },
}, { timestamps: true });

const DiscussionSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true, maxlength: 200 },
  content: { type: String, required: true, maxlength: 10000 },
  category: { type: String, enum: ['beginner', 'intermediate', 'advanced'], default: 'beginner' },
  tags: [{ type: String, maxlength: 50 }],
  author: {
    _id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String, avatar: String, reputation: Number
  },
  views: { type: Number, default: 0 },
  upvotes: [{ type: String }],
  commentCount: { type: Number, default: 0 },
}, { timestamps: true });

const CommentSchema = new mongoose.Schema({
  discussionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Discussion', required: true },
  content: { type: String, required: true, maxlength: 5000 },
  author: {
    _id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String, avatar: String, reputation: Number
  },
  upvotes: [{ type: String }],
}, { timestamps: true });

const CircleSchema = new mongoose.Schema({
  name: { type: String, required: true, maxlength: 100 },
  description: { type: String, maxlength: 500 },
  category: String,
  members: { type: Number, default: 0 },
  isPrivate: { type: Boolean, default: false },
  icon: String,
  color: String,
  memberIds: [{ type: String }],
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', UserSchema);
const Discussion = mongoose.models.Discussion || mongoose.model('Discussion', DiscussionSchema);
const Comment = mongoose.models.Comment || mongoose.model('Comment', CommentSchema);
const Circle = mongoose.models.Circle || mongoose.model('Circle', CircleSchema);

function sanitizeString(str, maxLen) {
  if (typeof str !== 'string') return '';
  maxLen = maxLen || 1000;
  return str.trim().slice(0, maxLen).replace(/[\x00-\x1F\x7F]/g, '');
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.use(async (req, res, next) => {
  try { await connectDB(); next(); } catch (e) { res.status(503).json({ success: false, message: 'خطأ في الاتصال بقاعدة البيانات' }); }
});

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'غير مصرح - يرجى تسجيل الدخول' });
  try {
    req.user = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ success: false, message: 'جلسة منتهية - يرجى تسجيل الدخول مجدداً' });
  }
}

app.get('/', (req, res) => res.json({ name: 'AporiaLab API', version: '3.1.0', status: 'running', database: 'MongoDB', security: 'enhanced' }));

app.get('/api/health', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const discussionCount = await Discussion.countDocuments();
    res.json({ status: 'OK', timestamp: new Date().toISOString(), database: 'connected', users: userCount, discussions: discussionCount });
  } catch (error) {
    res.status(500).json({ status: 'ERROR', message: error.message });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const email = sanitizeString(req.body.email, 200).toLowerCase();
    const password = req.body.password;
    if (!isValidEmail(email) || !password) return res.status(400).json({ success: false, message: 'بيانات غير صحيحة' });
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ success: false, message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ success: false, message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
    const token = jwt.sign({ userId: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: { id: user._id.toString(), _id: user._id.toString(), name: user.name, email: user.email, avatar: user.avatar, bio: user.bio, reputation: user.reputation, role: user.role } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const name = sanitizeString(req.body.name, 100);
    const email = sanitizeString(req.body.email, 200).toLowerCase();
    const password = req.body.password;
    if (!name || name.length < 2) return res.status(400).json({ success: false, message: 'الاسم يجب أن يكون حرفين على الأقل' });
    if (!isValidEmail(email)) return res.status(400).json({ success: false, message: 'البريد الإلكتروني غير صحيح' });
    if (!password || password.length < 6) return res.status(400).json({ success: false, message: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
    if (password.length > 200) return res.status(400).json({ success: false, message: 'كلمة المرور طويلة جداً' });
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ success: false, message: 'هذا البريد الإلكتروني مسجل مسبقاً' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      name, email, password: hashedPassword,
      avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=' + encodeURIComponent(email),
      bio: '', reputation: 0, role: 'user'
    });
    const token = jwt.sign({ userId: newUser._id.toString(), email: newUser.email }, JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({ success: true, token, user: { id: newUser._id.toString(), _id: newUser._id.toString(), name: newUser.name, email: newUser.email, avatar: newUser.avatar, bio: newUser.bio, reputation: newUser.reputation, role: newUser.role } });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    res.json({ success: true, user: { id: user._id.toString(), _id: user._id.toString(), name: user.name, email: user.email, avatar: user.avatar, bio: user.bio, reputation: user.reputation, role: user.role } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/discussions', async (req, res) => {
  try {
    const sort = req.query.sort || 'trending';
    const level = req.query.level;
    const filter = req.query.filter;
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 10));
    const query = {};
    if (level && level !== 'all') query.category = level;
    if (filter && filter !== 'all') query.category = filter;
    let sortObj = { createdAt: -1 };
    if (sort === 'trending') sortObj = { views: -1, createdAt: -1 };
    else if (sort === 'featured') sortObj = { upvotes: -1 };
    else if (sort === 'live') sortObj = { commentCount: -1 };
    const total = await Discussion.countDocuments(query);
    const discussions = await Discussion.find(query).sort(sortObj).skip((page - 1) * limit).limit(limit).lean();
    res.json({ success: true, discussions: discussions.map(d => Object.assign({}, d, { _id: d._id.toString() })), pagination: { page, pages: Math.ceil(total / limit), total } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/discussions/:id', async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    const discussion = await Discussion.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } }, { new: true }).lean();
    if (!discussion) return res.status(404).json({ success: false, message: 'النقاش غير موجود' });
    const comments = await Comment.find({ discussionId: req.params.id }).sort({ createdAt: -1 }).lean();
    res.json({ success: true, discussion: Object.assign({}, discussion, { _id: discussion._id.toString(), comments }) });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/discussions', authMiddleware, async (req, res) => {
  try {
    const title = sanitizeString(req.body.title, 200);
    const content = sanitizeString(req.body.content || req.body.description, 10000);
    const level = ['beginner', 'intermediate', 'advanced'].includes(req.body.level) ? req.body.level : 'beginner';
    const tags = Array.isArray(req.body.tags) ? req.body.tags.slice(0, 10).map(t => sanitizeString(t, 50)).filter(Boolean) : [];
    if (!title || title.length < 5) return res.status(400).json({ success: false, message: 'العنوان قصير جداً' });
    if (!content || content.length < 10) return res.status(400).json({ success: false, message: 'المحتوى قصير جداً' });
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    const newDiscussion = await Discussion.create({
      title, content, category: level, tags,
      author: { _id: user._id, name: user.name, avatar: user.avatar, reputation: user.reputation }
    });
    await User.findByIdAndUpdate(user._id, { $inc: { reputation: 10 } });
    res.status(201).json({ success: true, discussion: Object.assign({}, newDiscussion.toObject(), { _id: newDiscussion._id.toString() }) });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/discussions/:id/like', authMiddleware, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    const discussion = await Discussion.findById(req.params.id);
    if (!discussion) return res.status(404).json({ success: false, message: 'النقاش غير موجود' });
    const userId = req.user.userId;
    const likeIndex = discussion.upvotes.indexOf(userId);
    if (likeIndex === -1) discussion.upvotes.push(userId);
    else discussion.upvotes.splice(likeIndex, 1);
    await discussion.save();
    res.json({ success: true, liked: likeIndex === -1, upvotesCount: discussion.upvotes.length });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/discussions/:id/comments', authMiddleware, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    const discussion = await Discussion.findById(req.params.id);
    if (!discussion) return res.status(404).json({ success: false, message: 'النقاش غير موجود' });
    const content = sanitizeString(req.body.content, 5000);
    if (!content) return res.status(400).json({ success: false, message: 'محتوى التعليق مطلوب' });
    const user = await User.findById(req.user.userId);
    const newComment = await Comment.create({
      discussionId: req.params.id, content,
      author: { _id: user._id, name: user.name, avatar: user.avatar, reputation: user.reputation }
    });
    await Discussion.findByIdAndUpdate(req.params.id, { $inc: { commentCount: 1 } });
    res.status(201).json({ success: true, comment: Object.assign({}, newComment.toObject(), { _id: newComment._id.toString() }) });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/circles', async (req, res) => {
  try {
    const circles = await Circle.find().lean();
    res.json({ success: true, circles: circles.map(c => Object.assign({}, c, { _id: c._id.toString() })) });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/circles/:id', async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    const circle = await Circle.findById(req.params.id).lean();
    if (!circle) return res.status(404).json({ success: false, message: 'الدائرة غير موجودة' });
    res.json({ success: true, circle: Object.assign({}, circle, { _id: circle._id.toString() }) });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/circles/:id/join', authMiddleware, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    const circle = await Circle.findById(req.params.id);
    if (!circle) return res.status(404).json({ success: false, message: 'الدائرة غير موجودة' });
    const userId = req.user.userId;
    const memberIndex = circle.memberIds.indexOf(userId);
    if (memberIndex === -1) { circle.memberIds.push(userId); circle.members += 1; }
    else { circle.memberIds.splice(memberIndex, 1); circle.members = Math.max(0, circle.members - 1); }
    await circle.save();
    res.json({ success: true, joined: memberIndex === -1, members: circle.members });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/users/leaderboard', async (req, res) => {
  try {
    const users = await User.find().sort({ reputation: -1 }).limit(10).select('name avatar reputation role').lean();
    res.json({ success: true, users: users.map(u => Object.assign({}, u, { id: u._id.toString() })) });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/users/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    const userDiscussions = await Discussion.countDocuments({ 'author._id': user._id });
    res.json({ success: true, user: { id: user._id.toString(), _id: user._id.toString(), name: user.name, email: user.email, avatar: user.avatar, bio: user.bio, reputation: user.reputation, role: user.role, discussions: userDiscussions, createdAt: user.createdAt } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.put('/api/users/profile', authMiddleware, async (req, res) => {
  try {
    const updates = {};
    if (req.body.name !== undefined) updates.name = sanitizeString(req.body.name, 100);
    if (req.body.bio !== undefined) updates.bio = sanitizeString(req.body.bio, 500);
    if (req.body.avatar !== undefined) updates.avatar = sanitizeString(req.body.avatar, 500);
    const user = await User.findByIdAndUpdate(req.user.userId, updates, { new: true });
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    res.json({ success: true, user: { id: user._id.toString(), _id: user._id.toString(), name: user.name, email: user.email, avatar: user.avatar, bio: user.bio, reputation: user.reputation, role: user.role } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.use((req, res) => res.status(404).json({ success: false, message: 'المسار ' + req.path + ' غير موجود' }));
app.use((err, req, res, next) => {
  if (err.message === 'Not allowed by CORS') return res.status(403).json({ success: false, message: 'غير مسموح' });
  console.error(err.stack);
  res.status(500).json({ success: false, message: 'خطأ داخلي في الخادم' });
});

module.exports = app;
