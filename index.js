const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');

const app = express();

app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'", 'https:'],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

const allowedOrigins = [
  'https://aporialab.space',
  'https://www.aporialab.space',
  'https://aporialab-frontend.vercel.app',
  'http://localhost:5173',
  'http://localhost:3000',
];

const extraOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);
const allowedOriginsSet = new Set([...allowedOrigins, ...extraOrigins]);

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOriginsSet.has(origin)) return callback(null, true);
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

const googleAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'الكثير من محاولات تسجيل الدخول. حاول بعد 15 دقيقة.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});

app.use('/api/', generalLimiter);

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}
const MONGODB_URI = process.env.MONGODB_URI;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME || '';
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY || '';
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET || '';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const EMAIL_FROM = process.env.EMAIL_FROM || 'AporiaLab <onboarding@resend.dev>';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://aporialab.space';
const CLOUDINARY_AVATAR_FOLDER = 'aporialab/avatars';
const cloudinaryConfigured = () => Boolean(CLOUDINARY_CLOUD_NAME && CLOUDINARY_API_KEY && CLOUDINARY_API_SECRET);

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

const VALID_DURATIONS = {
  '12h': 12 * 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '3d': 3 * 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
};

const MAX_REACTIONS_PER_USER = 2;

const REPUTATION_REWARDS = {
  CREATE_DISCUSSION: 10,
  CREATE_COMMENT: 2,
  RECEIVE_UPVOTE: 5,
  RECEIVE_LOGICAL: 3,
  RECEIVE_INSPIRING: 2,
  RECEIVE_ILLOGICAL: -2,
  RECEIVE_UNCLEAR: -1,
};

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

const NotificationPreferencesSchema = new mongoose.Schema({
  comment: { type: Boolean, default: true },
  reply: { type: Boolean, default: true },
  discussion_upvote: { type: Boolean, default: true },
  comment_upvote: { type: Boolean, default: true },
  reaction_logical: { type: Boolean, default: true },
  reaction_inspiring: { type: Boolean, default: true },
  circle_join_request: { type: Boolean, default: true },
  circle_approved: { type: Boolean, default: true },
  circle_rejected: { type: Boolean, default: true },
}, { _id: false });

const USERNAME_PATTERN = /^[a-z0-9_]{3,30}$/;

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  username: {
    type: String,
    unique: true,
    sparse: true,
    lowercase: true,
    trim: true,
    minlength: 3,
    maxlength: 30,
    match: USERNAME_PATTERN,
    default: null,
  },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 200 },
  password: { type: String, default: '' },
  googleId: { type: String, default: null, sparse: true, index: true },
  authProvider: { type: String, enum: ['local', 'google'], default: 'local' },
  emailVerified: { type: Boolean, default: false },
  emailVerificationTokenHash: { type: String, default: null },
  emailVerificationTokenExpiry: { type: Date, default: null },
  passwordResetTokenHash: { type: String, default: null },
  passwordResetTokenExpiry: { type: Date, default: null },
  lastVerificationEmailSentAt: { type: Date, default: null },
  avatar: { type: String, default: '' },
  bio: { type: String, default: '', maxlength: 500 },
  location: { type: String, default: '', trim: true, maxlength: 100 },
  website: { type: String, default: '', trim: true, maxlength: 200 },
  reputation: { type: Number, default: 0 },
  role: { type: String, enum: ['user', 'moderator', 'admin'], default: 'user' },
  isFoundingMember: { type: Boolean, default: false },
  notificationPreferences: { type: NotificationPreferencesSchema, default: () => ({}) },
}, { timestamps: true });

const EditHistoryEntrySchema = new mongoose.Schema({
  editedAt: { type: Date, default: Date.now },
  editedBy: {
    _id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String,
  },
  previousTitle: String,
  previousContent: String,
  reason: { type: String, default: '' },
}, { _id: false });

const DiscussionSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true, maxlength: 200 },
  content: { type: String, required: true, maxlength: 10000 },
  category: { type: String, enum: ['beginner', 'intermediate', 'advanced'], default: 'beginner' },
  tags: [{ type: String, maxlength: 50 }],
  author: {
    _id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String, avatar: String, reputation: Number, isFoundingMember: Boolean
  },
  views: { type: Number, default: 0 },
  upvotes: [{ type: String }],
  commentCount: { type: Number, default: 0 },
  expiresAt: { type: Date, default: null },
  duration: { type: String, enum: ['12h', '24h', '3d', '7d', null], default: null },
  stanceStats: {
    pro: { type: Number, default: 0 },
    con: { type: Number, default: 0 },
    neutral: { type: Number, default: 0 },
  },
  editHistory: [EditHistoryEntrySchema],
  editedAt: { type: Date, default: null },
  editsCount: { type: Number, default: 0 },
}, { timestamps: true });

const CommentSchema = new mongoose.Schema({
  discussionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Discussion', required: true },
  content: { type: String, required: true, maxlength: 5000 },
  author: {
    _id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String, avatar: String, reputation: Number, isFoundingMember: Boolean
  },
  stance: { type: String, enum: ['pro', 'con', 'neutral'], required: true },
  upvotes: [{ type: String }],
  reactions: {
    logical: [{ type: String }],
    illogical: [{ type: String }],
    inspiring: [{ type: String }],
    unclear: [{ type: String }],
  },
  qualityScore: { type: Number, default: 0 },
  parentCommentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Comment', default: null },
  isReply: { type: Boolean, default: false },
  editedAt: { type: Date, default: null },
}, { timestamps: true });

const CircleSchema = new mongoose.Schema({
  name: { type: String, required: true, maxlength: 100 },
  description: { type: String, maxlength: 500 },
  category: String,
  members: { type: Number, default: 0 },
  isPrivate: { type: Boolean, default: false },
  icon: String,
  color: String,
  bannerColor: String,
  tags: [{ type: String }],
  memberIds: [{ type: String }],
  pendingRequests: [{ 
    userId: String,
    userName: String,
    userAvatar: String,
    requestedAt: { type: Date, default: Date.now },
    message: String,
  }],
  discussionCount: { type: Number, default: 0 },
  createdBy: {
    _id: String,
    name: String,
  },
}, { timestamps: true });

const NOTIFICATION_TYPES = [
  'comment',
  'reply',
  'discussion_upvote',
  'comment_upvote',
  'reaction_logical',
  'reaction_inspiring',
  'circle_join_request',
  'circle_approved',
  'circle_rejected',
];

const NotificationSchema = new mongoose.Schema({
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  sender: {
    _id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String,
    avatar: String,
  },
  type: { type: String, enum: NOTIFICATION_TYPES, required: true },
  title: { type: String, required: true, maxlength: 200 },
  message: { type: String, default: '', maxlength: 500 },
  link: { type: String, default: '', maxlength: 300 },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  isRead: { type: Boolean, default: false, index: true },
}, { timestamps: true });

DiscussionSchema.index({ createdAt: -1 });
DiscussionSchema.index({ views: -1, createdAt: -1 });
DiscussionSchema.index({ category: 1, createdAt: -1 });
DiscussionSchema.index({ 'author._id': 1, createdAt: -1 });
DiscussionSchema.index({ expiresAt: 1 });
DiscussionSchema.index({ title: 'text', content: 'text', tags: 'text' });

CommentSchema.index({ discussionId: 1, qualityScore: -1, createdAt: -1 });
CommentSchema.index({ parentCommentId: 1 });
CommentSchema.index({ 'author._id': 1, createdAt: -1 });

UserSchema.index({ reputation: -1 });
UserSchema.index({ emailVerificationTokenHash: 1 }, { sparse: true });
UserSchema.index({ passwordResetTokenHash: 1 }, { sparse: true });

NotificationSchema.index({ recipient: 1, isRead: 1, createdAt: -1 });
NotificationSchema.index({ recipient: 1, type: 1, createdAt: -1 });
NotificationSchema.index({ createdAt: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 60 });

const User = mongoose.models.User || mongoose.model('User', UserSchema);
const Discussion = mongoose.models.Discussion || mongoose.model('Discussion', DiscussionSchema);
const Comment = mongoose.models.Comment || mongoose.model('Comment', CommentSchema);
const Circle = mongoose.models.Circle || mongoose.model('Circle', CircleSchema);
const Notification = mongoose.models.Notification || mongoose.model('Notification', NotificationSchema);

async function createNotification({ recipient, sender, type, title, message, link, metadata }) {
  if (!recipient) return null;
  const recipientId = recipient.toString();
  const senderId = sender && sender._id ? sender._id.toString() : null;
  if (senderId && senderId === recipientId) return null;
  try {
    const recipientDoc = await User.findById(recipientId).select('notificationPreferences').lean();
    if (!recipientDoc) return null;
    const prefs = getNotificationPreferences(recipientDoc);
    if (prefs[type] === false) return null;

    const doc = await Notification.create({
      recipient: recipientId,
      sender: sender ? {
        _id: sender._id || null,
        name: sender.name || '',
        avatar: sender.avatar || '',
      } : undefined,
      type,
      title: title || '',
      message: message || '',
      link: link || '',
      metadata: metadata || {},
      isRead: false,
    });
    return doc;
  } catch (e) {
    console.error('createNotification failed:', e.message);
    return null;
  }
}

function sanitizeString(str, maxLen) {
  if (typeof str !== 'string') return '';
  maxLen = maxLen || 1000;
  return str.trim().slice(0, maxLen).replace(/[\x00-\x1F\x7F]/g, '');
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isDiscussionExpired(discussion) {
  if (!discussion.expiresAt) return false;
  return new Date() > new Date(discussion.expiresAt);
}

function calculateQualityScore(comment) {
  const upvotes = (comment.upvotes || []).length;
  const logical = (comment.reactions?.logical || []).length;
  const illogical = (comment.reactions?.illogical || []).length;
  const inspiring = (comment.reactions?.inspiring || []).length;
  const unclear = (comment.reactions?.unclear || []).length;
  
  const positive = upvotes * 3 + logical * 2 + inspiring * 1.5;
  const negative = illogical * 2 + unclear * 0.5;
  
  return Math.round(positive - negative);
}

function getNotificationPreferences(user) {
  const stored = (user && user.notificationPreferences) || {};
  const out = {};
  for (const type of NOTIFICATION_TYPES) {
    out[type] = stored[type] === false ? false : true;
  }
  return out;
}

function slugifyForUsername(input) {
  if (typeof input !== 'string') return '';
  const noCombining = input.normalize('NFKD').replace(/[̀-ͯ]/g, '');
  return noCombining
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 24);
}

async function ensureUsernameForUser(user) {
  if (user.username) return user;
  const baseRaw = slugifyForUsername(user.name) || slugifyForUsername(user.email.split('@')[0]) || 'user';
  const base = baseRaw.length < 3 ? (baseRaw + '_user').slice(0, 24) : baseRaw;
  for (let attempt = 0; attempt < 12; attempt++) {
    const suffix = attempt === 0 ? '' : '_' + Math.random().toString(36).slice(2, 6);
    const candidate = (base + suffix).slice(0, 30);
    if (!USERNAME_PATTERN.test(candidate)) continue;
    const taken = await User.exists({ username: candidate });
    if (!taken) {
      user.username = candidate;
      await user.save();
      return user;
    }
  }
  const fallback = ('u_' + user._id.toString().slice(-10)).slice(0, 30);
  user.username = fallback;
  await user.save();
  return user;
}

function userToResponse(user) {
  return {
    id: user._id.toString(),
    _id: user._id.toString(),
    username: user.username || null,
    name: user.name,
    email: user.email,
    avatar: user.avatar,
    bio: user.bio,
    location: user.location || '',
    website: user.website || '',
    reputation: user.reputation,
    role: user.role,
    isFoundingMember: user.isFoundingMember,
    authProvider: user.authProvider,
    emailVerified: user.emailVerified,
    notificationPreferences: getNotificationPreferences(user),
  };
}

function generateAuthToken(ttlMs) {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const expiry = new Date(Date.now() + ttlMs);
  return { token, tokenHash, expiry };
}

function hashAuthToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

async function sendEmail({ to, subject, html, text }) {
  if (!RESEND_API_KEY) throw new Error('RESEND_API_KEY is not configured');
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + RESEND_API_KEY,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from: EMAIL_FROM, to, subject, html, text }),
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error('Resend API ' + response.status + ': ' + body);
  }
  return await response.json();
}

async function sendVerificationEmail(user, plainToken) {
  const link = FRONTEND_URL + '/verify-email/' + plainToken;
  const safeName = escapeHtml(user.name || '');
  const safeLink = escapeHtml(link);
  const subject = 'وثق بريدك الالكتروني - Verify your AporiaLab email';
  const text = 'مرحباً ' + (user.name || '') + '،\n\n'
    + 'لتفعيل حسابك في AporiaLab والمشاركة في النقاشات، يرجى تأكيد بريدك الالكتروني عبر الرابط التالي:\n'
    + link + '\n\n'
    + 'هذا الرابط صالح لمدة 24 ساعة.\n\n'
    + 'إذا لم تنشئ هذا الحساب يمكنك تجاهل هذه الرسالة.\n\n'
    + 'AporiaLab';
  const html = '<div dir="rtl" style="font-family: system-ui, sans-serif; max-width: 560px; margin: 0 auto; padding: 24px; color: #111;">'
    + '<h2 style="color: #111;">وثق بريدك الالكتروني</h2>'
    + '<p>مرحباً ' + safeName + '،</p>'
    + '<p>لتفعيل حسابك في AporiaLab والمشاركة في النقاشات، اضغط على الزر التالي:</p>'
    + '<p style="margin: 24px 0;"><a href="' + safeLink + '" style="background: #0f172a; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">توثيق البريد الالكتروني</a></p>'
    + '<p style="color: #555; font-size: 14px;">أو انسخ الرابط التالي إلى متصفحك:</p>'
    + '<p style="word-break: break-all; color: #555; font-size: 13px;">' + safeLink + '</p>'
    + '<p style="color: #888; font-size: 13px; margin-top: 24px;">هذا الرابط صالح لمدة 24 ساعة. إذا لم تنشئ هذا الحساب يمكنك تجاهل هذه الرسالة.</p>'
    + '<hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;" />'
    + '<p style="color: #888; font-size: 12px;">AporiaLab - منصة النقاش الفلسفي</p>'
    + '</div>';
  try {
    await sendEmail({ to: user.email, subject, html, text });
    return true;
  } catch (e) {
    console.error('sendVerificationEmail failed:', e.message);
    return false;
  }
}

async function sendPasswordResetEmail(user, plainToken) {
  const link = FRONTEND_URL + '/reset-password/' + plainToken;
  const safeName = escapeHtml(user.name || '');
  const safeLink = escapeHtml(link);
  const subject = 'إعادة تعيين كلمة المرور - Reset your AporiaLab password';
  const text = 'مرحباً ' + (user.name || '') + '،\n\n'
    + 'تلقينا طلباً لإعادة تعيين كلمة مرور حسابك في AporiaLab. لإعادة التعيين اضغط على الرابط التالي:\n'
    + link + '\n\n'
    + 'هذا الرابط صالح لمدة ساعة واحدة فقط.\n\n'
    + 'إذا لم تطلب إعادة التعيين يمكنك تجاهل هذه الرسالة، وستظل كلمة مرورك الحالية كما هي.\n\n'
    + 'AporiaLab';
  const html = '<div dir="rtl" style="font-family: system-ui, sans-serif; max-width: 560px; margin: 0 auto; padding: 24px; color: #111;">'
    + '<h2 style="color: #111;">إعادة تعيين كلمة المرور</h2>'
    + '<p>مرحباً ' + safeName + '،</p>'
    + '<p>تلقينا طلباً لإعادة تعيين كلمة مرور حسابك. اضغط على الزر التالي لاختيار كلمة مرور جديدة:</p>'
    + '<p style="margin: 24px 0;"><a href="' + safeLink + '" style="background: #0f172a; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">إعادة تعيين كلمة المرور</a></p>'
    + '<p style="color: #555; font-size: 14px;">أو انسخ الرابط التالي إلى متصفحك:</p>'
    + '<p style="word-break: break-all; color: #555; font-size: 13px;">' + safeLink + '</p>'
    + '<p style="color: #888; font-size: 13px; margin-top: 24px;">هذا الرابط صالح لمدة ساعة واحدة فقط. إذا لم تطلب إعادة التعيين يمكنك تجاهل هذه الرسالة.</p>'
    + '<hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;" />'
    + '<p style="color: #888; font-size: 12px;">AporiaLab - منصة النقاش الفلسفي</p>'
    + '</div>';
  try {
    await sendEmail({ to: user.email, subject, html, text });
    return true;
  } catch (e) {
    console.error('sendPasswordResetEmail failed:', e.message);
    return false;
  }
}

async function updateAuthorReputation(authorId, points) {
  if (!authorId || !points) return;
  try {
    await User.findByIdAndUpdate(authorId, { $inc: { reputation: points } });
  } catch (e) {
    console.error('Reputation update failed:', e.message);
  }
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

async function requireVerifiedEmail(req, res, next) {
  try {
    const u = await User.findById(req.user.userId).select('emailVerified authProvider').lean();
    if (!u) return res.status(401).json({ success: false, message: 'المستخدم غير موجود' });
    if (u.authProvider === 'google' || u.emailVerified === true) return next();
    return res.status(403).json({
      success: false,
      message: 'يجب توثيق بريدك الالكتروني قبل المشاركة',
      code: 'EMAIL_NOT_VERIFIED',
    });
  } catch (e) {
    console.error('requireVerifiedEmail error:', e.message);
    return res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
}

async function adminMiddleware(req, res, next) {
  try {
    if (!ADMIN_KEY) {
      return res.status(503).json({ success: false, message: 'وظائف الإدارة غير مفعّلة' });
    }
    const providedKey = req.headers['x-admin-key'];
    if (!providedKey || providedKey !== ADMIN_KEY) {
      return res.status(403).json({ success: false, message: 'غير مصرح' });
    }
    const user = await User.findById(req.user.userId);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'صلاحيات الإدارة مطلوبة' });
    }
    req.adminUser = user;
    next();
  } catch (e) {
    return res.status(500).json({ success: false, message: 'خطأ في التحقق من صلاحيات الإدارة' });
  }
}

app.get('/', (req, res) => res.json({ 
  name: 'AporiaLab API', 
  version: '4.1.0', 
  status: 'running', 
  database: 'MongoDB', 
  security: 'enhanced', 
  auth: 'local + google', 
  features: 'stances + reactions + timer + replies + edit history + reputation system' 
}));

app.get('/api/health', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const discussionCount = await Discussion.countDocuments();
    res.json({ status: 'OK', timestamp: new Date().toISOString(), database: 'connected', users: userCount, discussions: discussionCount });
  } catch (error) {
    res.status(500).json({ status: 'ERROR', message: error.message });
  }
});

app.get('/api/stats', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const discussionCount = await Discussion.countDocuments();
    const circleCount = await Circle.countDocuments();
    const commentCount = await Comment.countDocuments();
    res.json({
      success: true,
      stats: {
        users: userCount,
        discussions: discussionCount,
        circles: circleCount,
        comments: commentCount,
        contributions: discussionCount + commentCount
      }
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/auth/google', googleAuthLimiter, async (req, res) => {
  try {
    if (!GOOGLE_CLIENT_ID) {
      return res.status(503).json({ success: false, message: 'خدمة Google غير مفعّلة على الخادم' });
    }

    const credential = req.body.credential;
    if (!credential || typeof credential !== 'string') {
      return res.status(400).json({ success: false, message: 'بيانات Google غير صحيحة' });
    }

    let payload;
    try {
      const ticket = await googleClient.verifyIdToken({
        idToken: credential,
        audience: GOOGLE_CLIENT_ID,
      });
      payload = ticket.getPayload();
    } catch (verifyError) {
      console.error('Google token verification failed:', verifyError.message);
      return res.status(401).json({ success: false, message: 'فشل التحقق من Google' });
    }

    if (!payload || !payload.email) {
      return res.status(401).json({ success: false, message: 'بيانات Google غير مكتملة' });
    }

    if (!payload.email_verified) {
      return res.status(403).json({ success: false, message: 'بريدك الإلكتروني في Google غير موثّق' });
    }

    const googleId = payload.sub;
    const email = payload.email.toLowerCase();
    const googleName = payload.name || payload.given_name || email.split('@')[0];
    const googlePicture = payload.picture || '';

    let user = await User.findOne({ googleId });

    if (!user) {
      user = await User.findOne({ email });

      if (user) {
        user.googleId = googleId;
        user.authProvider = 'google';
        user.emailVerified = true;
        if (!user.avatar && googlePicture) user.avatar = googlePicture;
        await user.save();
      } else {
        const randomPassword = await bcrypt.hash(googleId + Date.now().toString(), 10);
        user = await User.create({
          name: sanitizeString(googleName, 100),
          email,
          password: randomPassword,
          googleId,
          authProvider: 'google',
          emailVerified: true,
          avatar: googlePicture || ('https://api.dicebear.com/7.x/avataaars/svg?seed=' + encodeURIComponent(email)),
          bio: '',
          reputation: 0,
          role: 'user',
          isFoundingMember: false
        });
      }
    }

    if (!user.username) {
      user = await ensureUsernameForUser(user);
    }

    const token = jwt.sign(
      { userId: user._id.toString(), email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({ success: true, token, user: userToResponse(user) });
  } catch (error) {
    console.error('Google auth error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const email = sanitizeString(req.body.email, 200).toLowerCase();
    const password = req.body.password;
    if (!isValidEmail(email) || !password) return res.status(400).json({ success: false, message: 'بيانات غير صحيحة' });
    let user = await User.findOne({ email });
    if (!user) return res.status(401).json({ success: false, message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
    if (user.authProvider === 'google' && !user.password) {
      return res.status(401).json({ success: false, message: 'هذا الحساب يُسجّل الدخول بـ Google' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ success: false, message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
    if (!user.username) user = await ensureUsernameForUser(user);
    const token = jwt.sign({ userId: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: userToResponse(user) });
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
    let newUser = await User.create({
      name, email, password: hashedPassword,
      authProvider: 'local',
      emailVerified: false,
      avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=' + encodeURIComponent(email),
      bio: '', reputation: 0, role: 'user', isFoundingMember: false
    });
    newUser = await ensureUsernameForUser(newUser);

    const { token: verifyToken, tokenHash: verifyHash, expiry: verifyExpiry } = generateAuthToken(24 * 60 * 60 * 1000);
    newUser.emailVerificationTokenHash = verifyHash;
    newUser.emailVerificationTokenExpiry = verifyExpiry;
    newUser.lastVerificationEmailSentAt = new Date();
    await newUser.save();
    sendVerificationEmail(newUser, verifyToken).catch((e) => console.error('Verification email failed on register:', e.message));

    const token = jwt.sign({ userId: newUser._id.toString(), email: newUser.email }, JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({ success: true, token, user: userToResponse(newUser) });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/auth/verify-email', async (req, res) => {
  try {
    const token = typeof req.body.token === 'string' ? req.body.token.trim() : '';
    if (!/^[a-f0-9]{64}$/.test(token)) {
      return res.status(400).json({ success: false, message: 'رابط التوثيق غير صالح' });
    }
    const tokenHash = hashAuthToken(token);
    const user = await User.findOne({ emailVerificationTokenHash: tokenHash });
    if (!user) return res.status(400).json({ success: false, message: 'رابط التوثيق غير صالح أو سبق استخدامه' });
    if (!user.emailVerificationTokenExpiry || user.emailVerificationTokenExpiry.getTime() < Date.now()) {
      user.emailVerificationTokenHash = null;
      user.emailVerificationTokenExpiry = null;
      await user.save();
      return res.status(400).json({ success: false, message: 'انتهت صلاحية رابط التوثيق، أعد طلب التوثيق' });
    }
    user.emailVerified = true;
    user.emailVerificationTokenHash = null;
    user.emailVerificationTokenExpiry = null;
    await user.save();
    const authToken = jwt.sign({ userId: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token: authToken, user: userToResponse(user), message: 'تم توثيق البريد الإلكتروني' });
  } catch (error) {
    console.error('Verify email error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/auth/resend-verification', authMiddleware, async (req, res) => {
  try {
    if (!RESEND_API_KEY) return res.status(503).json({ success: false, message: 'إرسال البريد غير مفعّل' });
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    if (user.emailVerified) return res.json({ success: true, message: 'بريدك موثّق مسبقاً' });
    if (user.lastVerificationEmailSentAt && Date.now() - user.lastVerificationEmailSentAt.getTime() < 60_000) {
      return res.status(429).json({ success: false, message: 'انتظر دقيقة قبل إعادة الإرسال' });
    }
    const { token, tokenHash, expiry } = generateAuthToken(24 * 60 * 60 * 1000);
    user.emailVerificationTokenHash = tokenHash;
    user.emailVerificationTokenExpiry = expiry;
    user.lastVerificationEmailSentAt = new Date();
    await user.save();
    sendVerificationEmail(user, token).catch((e) => console.error('Resend verification email failed:', e.message));
    res.json({ success: true, message: 'أرسلنا رسالة جديدة إلى بريدك' });
  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
  const genericMessage = 'إذا كان البريد مسجّلاً ستصلك رسالة لإعادة تعيين كلمة المرور';
  try {
    const email = sanitizeString(req.body.email || '', 200).toLowerCase();
    if (!isValidEmail(email)) {
      return res.json({ success: true, message: genericMessage });
    }
    const user = await User.findOne({ email });
    if (user && user.authProvider !== 'google') {
      const { token, tokenHash, expiry } = generateAuthToken(60 * 60 * 1000);
      user.passwordResetTokenHash = tokenHash;
      user.passwordResetTokenExpiry = expiry;
      await user.save();
      sendPasswordResetEmail(user, token).catch((e) => console.error('Password reset email failed:', e.message));
    }
    res.json({ success: true, message: genericMessage });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.json({ success: true, message: genericMessage });
  }
});

app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  try {
    const token = typeof req.body.token === 'string' ? req.body.token.trim() : '';
    const newPassword = req.body.newPassword;
    if (!/^[a-f0-9]{64}$/.test(token)) {
      return res.status(400).json({ success: false, message: 'رابط إعادة التعيين غير صالح' });
    }
    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 6) {
      return res.status(400).json({ success: false, message: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
    }
    if (newPassword.length > 200) {
      return res.status(400).json({ success: false, message: 'كلمة المرور طويلة جداً' });
    }
    const tokenHash = hashAuthToken(token);
    const user = await User.findOne({ passwordResetTokenHash: tokenHash });
    if (!user) return res.status(400).json({ success: false, message: 'رابط إعادة التعيين غير صالح أو سبق استخدامه' });
    if (!user.passwordResetTokenExpiry || user.passwordResetTokenExpiry.getTime() < Date.now()) {
      user.passwordResetTokenHash = null;
      user.passwordResetTokenExpiry = null;
      await user.save();
      return res.status(400).json({ success: false, message: 'انتهت صلاحية الرابط، اطلب إعادة تعيين جديدة' });
    }
    user.password = await bcrypt.hash(newPassword, 10);
    user.passwordResetTokenHash = null;
    user.passwordResetTokenExpiry = null;
    await user.save();
    res.json({ success: true, message: 'تم تحديث كلمة المرور، يمكنك الآن تسجيل الدخول' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    let user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    if (!user.username) {
      user = await ensureUsernameForUser(user);
    }
    res.json({ success: true, user: userToResponse(user) });
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
    res.json({ 
      success: true, 
      discussions: discussions.map(d => Object.assign({}, d, { 
        _id: d._id.toString(),
        isExpired: isDiscussionExpired(d)
      })), 
      pagination: { page, pages: Math.ceil(total / limit), total } 
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/discussions/:id', async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    const discussion = await Discussion.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } }, { new: true }).lean();
    if (!discussion) return res.status(404).json({ success: false, message: 'النقاش غير موجود' });

    const commentsPage = Math.max(1, parseInt(req.query.commentsPage) || 1);
    const commentsLimit = Math.min(100, Math.max(5, parseInt(req.query.commentsLimit) || 50));
    const commentsSkip = (commentsPage - 1) * commentsLimit;

    const [totalComments, comments] = await Promise.all([
      Comment.countDocuments({ discussionId: req.params.id }),
      Comment.find({ discussionId: req.params.id })
        .sort({ qualityScore: -1, createdAt: -1 })
        .skip(commentsSkip)
        .limit(commentsLimit)
        .lean(),
    ]);

    const enrichedComments = comments.map(c => ({
      ...c,
      _id: c._id.toString(),
      parentCommentId: c.parentCommentId ? c.parentCommentId.toString() : null,
      reactions: {
        logical: c.reactions?.logical || [],
        illogical: c.reactions?.illogical || [],
        inspiring: c.reactions?.inspiring || [],
        unclear: c.reactions?.unclear || [],
      }
    }));

    res.json({
      success: true,
      discussion: Object.assign({}, discussion, {
        _id: discussion._id.toString(),
        comments: enrichedComments,
        isExpired: isDiscussionExpired(discussion)
      }),
      commentsPagination: {
        page: commentsPage,
        limit: commentsLimit,
        total: totalComments,
        pages: Math.ceil(totalComments / commentsLimit),
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/discussions/:id/history', async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    }
    const discussion = await Discussion.findById(req.params.id).lean();
    if (!discussion) return res.status(404).json({ success: false, message: 'النقاش غير موجود' });
    
    res.json({
      success: true,
      editHistory: discussion.editHistory || [],
      editsCount: discussion.editsCount || 0,
      editedAt: discussion.editedAt,
      currentTitle: discussion.title,
      currentContent: discussion.content,
    });
  } catch (error) {
    console.error('Get history error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/discussions', authMiddleware, requireVerifiedEmail, async (req, res) => {
  try {
    const title = sanitizeString(req.body.title, 200);
    const content = sanitizeString(req.body.content || req.body.description, 10000);
    const level = ['beginner', 'intermediate', 'advanced'].includes(req.body.level) ? req.body.level : 'beginner';
    const tags = Array.isArray(req.body.tags) ? req.body.tags.slice(0, 10).map(t => sanitizeString(t, 50)).filter(Boolean) : [];
    const duration = req.body.duration && Object.keys(VALID_DURATIONS).includes(req.body.duration) ? req.body.duration : null;
    
    if (!title || title.length < 5) return res.status(400).json({ success: false, message: 'العنوان قصير جداً' });
    if (!content || content.length < 10) return res.status(400).json({ success: false, message: 'المحتوى قصير جداً' });
    
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    
    const expiresAt = duration ? new Date(Date.now() + VALID_DURATIONS[duration]) : null;
    
    const newDiscussion = await Discussion.create({
      title, content, category: level, tags,
      author: { 
        _id: user._id, 
        name: user.name, 
        avatar: user.avatar, 
        reputation: user.reputation,
        isFoundingMember: user.isFoundingMember
      },
      duration,
      expiresAt,
      stanceStats: { pro: 0, con: 0, neutral: 0 },
      editHistory: [],
      editsCount: 0,
    });
    await updateAuthorReputation(user._id, REPUTATION_REWARDS.CREATE_DISCUSSION);
    res.status(201).json({ 
      success: true, 
      discussion: Object.assign({}, newDiscussion.toObject(), { 
        _id: newDiscussion._id.toString(),
        isExpired: false
      }) 
    });
  } catch (error) {
    console.error('Create discussion error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.patch('/api/discussions/:id', authMiddleware, requireVerifiedEmail, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    }
    const discussion = await Discussion.findById(req.params.id);
    if (!discussion) return res.status(404).json({ success: false, message: 'النقاش غير موجود' });
    
    const userId = req.user.userId;
    const isOwner = discussion.author._id.toString() === userId;
    const currentUser = await User.findById(userId);
    const isAdmin = currentUser && (currentUser.role === 'admin' || currentUser.role === 'moderator');
    if (!isOwner && !isAdmin) {
      return res.status(403).json({ success: false, message: 'غير مسموح بتعديل هذا النقاش' });
    }
    
    const newTitle = req.body.title !== undefined ? sanitizeString(req.body.title, 200) : null;
    const newContent = req.body.content !== undefined ? sanitizeString(req.body.content, 10000) : null;
    const reason = sanitizeString(req.body.reason || '', 200);
    
    if (newTitle !== null && (!newTitle || newTitle.length < 5)) {
      return res.status(400).json({ success: false, message: 'العنوان قصير جداً' });
    }
    if (newContent !== null && (!newContent || newContent.length < 10)) {
      return res.status(400).json({ success: false, message: 'المحتوى قصير جداً' });
    }
    
    const titleChanged = newTitle !== null && newTitle !== discussion.title;
    const contentChanged = newContent !== null && newContent !== discussion.content;
    
    if (!titleChanged && !contentChanged) {
      return res.status(400).json({ success: false, message: 'لم يتغير شيء' });
    }
    
    discussion.editHistory.push({
      editedAt: new Date(),
      editedBy: { _id: currentUser._id, name: currentUser.name },
      previousTitle: discussion.title,
      previousContent: discussion.content,
      reason: reason,
    });
    
    if (titleChanged) discussion.title = newTitle;
    if (contentChanged) discussion.content = newContent;
    discussion.editedAt = new Date();
    discussion.editsCount = (discussion.editsCount || 0) + 1;
    
    await discussion.save();
    
    res.json({ 
      success: true, 
      discussion: Object.assign({}, discussion.toObject(), { 
        _id: discussion._id.toString(),
        isExpired: isDiscussionExpired(discussion)
      }),
      message: 'تم تعديل النقاش'
    });
  } catch (error) {
    console.error('Edit discussion error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.delete('/api/discussions/:id', authMiddleware, requireVerifiedEmail, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    }
    const discussion = await Discussion.findById(req.params.id);
    if (!discussion) return res.status(404).json({ success: false, message: 'النقاش غير موجود' });
    
    const userId = req.user.userId;
    const isOwner = discussion.author._id.toString() === userId;
    const currentUser = await User.findById(userId);
    const isAdmin = currentUser && (currentUser.role === 'admin' || currentUser.role === 'moderator');
    if (!isOwner && !isAdmin) {
      return res.status(403).json({ success: false, message: 'غير مسموح بحذف هذا النقاش' });
    }
    
    await Comment.deleteMany({ discussionId: req.params.id });
    await Discussion.findByIdAndDelete(req.params.id);
    
    res.json({ success: true, message: 'تم حذف النقاش' });
  } catch (error) {
    console.error('Delete discussion error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/discussions/:id/like', authMiddleware, requireVerifiedEmail, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    const discussion = await Discussion.findById(req.params.id);
    if (!discussion) return res.status(404).json({ success: false, message: 'النقاش غير موجود' });
    if (isDiscussionExpired(discussion)) return res.status(403).json({ success: false, message: 'انتهى وقت النقاش' });
    const userId = req.user.userId;
    const likeIndex = discussion.upvotes.indexOf(userId);
    const isLiking = likeIndex === -1;
    if (isLiking) discussion.upvotes.push(userId);
    else discussion.upvotes.splice(likeIndex, 1);
    await discussion.save();

    if (isLiking && discussion.author && discussion.author._id) {
      const sender = await User.findById(userId).select('name avatar').lean();
      await createNotification({
        recipient: discussion.author._id,
        sender: sender ? { _id: userId, name: sender.name, avatar: sender.avatar } : { _id: userId },
        type: 'discussion_upvote',
        title: 'إعجاب جديد بنقاشك',
        message: discussion.title,
        link: '/discussion/' + discussion._id.toString(),
        metadata: { discussionId: discussion._id.toString() },
      });
    }

    res.json({ success: true, liked: isLiking, upvotesCount: discussion.upvotes.length });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/discussions/:id/comments', authMiddleware, requireVerifiedEmail, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    const discussion = await Discussion.findById(req.params.id);
    if (!discussion) return res.status(404).json({ success: false, message: 'النقاش غير موجود' });
    if (isDiscussionExpired(discussion)) return res.status(403).json({ success: false, message: 'انتهى وقت النقاش - لا يمكن إضافة تعليقات جديدة' });
    
    const content = sanitizeString(req.body.content, 5000);
    const stance = req.body.stance;
    const parentCommentId = req.body.parentCommentId || null;
    
    if (!content) return res.status(400).json({ success: false, message: 'محتوى التعليق مطلوب' });
    
    let isReply = false;
    let validParentId = null;
    let finalStance = stance;
    let parentAuthorId = null;

    if (parentCommentId) {
      if (!mongoose.Types.ObjectId.isValid(parentCommentId)) {
        return res.status(400).json({ success: false, message: 'معرف التعليق الأصلي غير صحيح' });
      }
      const parentComment = await Comment.findById(parentCommentId);
      if (!parentComment) {
        return res.status(404).json({ success: false, message: 'التعليق الأصلي غير موجود' });
      }
      if (parentComment.discussionId.toString() !== req.params.id) {
        return res.status(400).json({ success: false, message: 'التعليق الأصلي ينتمي لنقاش مختلف' });
      }
      isReply = true;
      validParentId = parentComment._id;
      finalStance = parentComment.stance;
      parentAuthorId = parentComment.author && parentComment.author._id ? parentComment.author._id : null;
    } else {
      if (!['pro', 'con', 'neutral'].includes(stance)) {
        return res.status(400).json({ success: false, message: 'يجب اختيار موقف (مع/ضد/محايد)' });
      }
    }
    
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    
    const newComment = await Comment.create({
      discussionId: req.params.id, 
      content,
      stance: finalStance,
      author: { 
        _id: user._id, 
        name: user.name, 
        avatar: user.avatar, 
        reputation: user.reputation,
        isFoundingMember: user.isFoundingMember
      },
      reactions: {
        logical: [],
        illogical: [],
        inspiring: [],
        unclear: [],
      },
      qualityScore: 0,
      parentCommentId: validParentId,
      isReply,
    });
    
    if (!isReply) {
      const stanceField = `stanceStats.${finalStance}`;
      await Discussion.findByIdAndUpdate(req.params.id, { 
        $inc: { commentCount: 1, [stanceField]: 1 } 
      });
    } else {
      await Discussion.findByIdAndUpdate(req.params.id, { 
        $inc: { commentCount: 1 } 
      });
    }
    
    await updateAuthorReputation(user._id, REPUTATION_REWARDS.CREATE_COMMENT);

    const senderInfo = { _id: user._id, name: user.name, avatar: user.avatar };
    const commentLink = '/discussion/' + req.params.id + '#c-' + newComment._id.toString();
    if (isReply && parentAuthorId) {
      await createNotification({
        recipient: parentAuthorId,
        sender: senderInfo,
        type: 'reply',
        title: 'ردّ جديد على تعليقك',
        message: content.slice(0, 200),
        link: commentLink,
        metadata: {
          discussionId: req.params.id,
          commentId: newComment._id.toString(),
          parentCommentId: validParentId ? validParentId.toString() : null,
        },
      });
    } else if (!isReply && discussion.author && discussion.author._id) {
      await createNotification({
        recipient: discussion.author._id,
        sender: senderInfo,
        type: 'comment',
        title: 'تعليق جديد على نقاشك',
        message: content.slice(0, 200),
        link: commentLink,
        metadata: {
          discussionId: req.params.id,
          commentId: newComment._id.toString(),
        },
      });
    }

    res.status(201).json({
      success: true,
      comment: Object.assign({}, newComment.toObject(), {
        _id: newComment._id.toString(),
        parentCommentId: validParentId ? validParentId.toString() : null,
      })
    });
  } catch (error) {
    console.error('Add comment error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.patch('/api/comments/:id', authMiddleware, requireVerifiedEmail, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    }
    const comment = await Comment.findById(req.params.id);
    if (!comment) return res.status(404).json({ success: false, message: 'التعليق غير موجود' });
    
    const userId = req.user.userId;
    const isOwner = comment.author._id.toString() === userId;
    const currentUser = await User.findById(userId);
    const isAdmin = currentUser && (currentUser.role === 'admin' || currentUser.role === 'moderator');
    if (!isOwner && !isAdmin) {
      return res.status(403).json({ success: false, message: 'غير مسموح بتعديل هذا التعليق' });
    }
    
    const discussion = await Discussion.findById(comment.discussionId);
    if (discussion && isDiscussionExpired(discussion)) {
      return res.status(403).json({ success: false, message: 'انتهى وقت النقاش' });
    }
    
    const newContent = sanitizeString(req.body.content, 5000);
    if (!newContent || newContent.length < 1) {
      return res.status(400).json({ success: false, message: 'محتوى التعليق مطلوب' });
    }
    if (newContent === comment.content) {
      return res.status(400).json({ success: false, message: 'لم يتغير شيء' });
    }
    
    comment.content = newContent;
    comment.editedAt = new Date();
    await comment.save();
    
    res.json({ 
      success: true, 
      comment: Object.assign({}, comment.toObject(), { 
        _id: comment._id.toString(),
        parentCommentId: comment.parentCommentId ? comment.parentCommentId.toString() : null,
      }),
      message: 'تم تعديل التعليق'
    });
  } catch (error) {
    console.error('Edit comment error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/comments/:id/upvote', authMiddleware, requireVerifiedEmail, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    }
    const comment = await Comment.findById(req.params.id);
    if (!comment) return res.status(404).json({ success: false, message: 'التعليق غير موجود' });
    
    const discussion = await Discussion.findById(comment.discussionId);
    if (discussion && isDiscussionExpired(discussion)) {
      return res.status(403).json({ success: false, message: 'انتهى وقت النقاش' });
    }
    
    const userId = req.user.userId;
    const upvoteIndex = comment.upvotes.indexOf(userId);
    const isUpvoting = upvoteIndex === -1;
    
    if (isUpvoting) {
      comment.upvotes.push(userId);
    } else {
      comment.upvotes.splice(upvoteIndex, 1);
    }
    
    comment.qualityScore = calculateQualityScore(comment);
    await comment.save();
    
    if (comment.author._id.toString() !== userId) {
      const reputationChange = isUpvoting ? REPUTATION_REWARDS.RECEIVE_UPVOTE : -REPUTATION_REWARDS.RECEIVE_UPVOTE;
      await updateAuthorReputation(comment.author._id, reputationChange);
    }

    if (isUpvoting && comment.author && comment.author._id) {
      const sender = await User.findById(userId).select('name avatar').lean();
      await createNotification({
        recipient: comment.author._id,
        sender: sender ? { _id: userId, name: sender.name, avatar: sender.avatar } : { _id: userId },
        type: 'comment_upvote',
        title: 'إعجاب جديد بتعليقك',
        message: (comment.content || '').slice(0, 200),
        link: '/discussion/' + comment.discussionId.toString() + '#c-' + comment._id.toString(),
        metadata: {
          discussionId: comment.discussionId.toString(),
          commentId: comment._id.toString(),
        },
      });
    }

    res.json({
      success: true,
      upvoted: isUpvoting, 
      upvotesCount: comment.upvotes.length,
      qualityScore: comment.qualityScore
    });
  } catch (error) {
    console.error('Upvote comment error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

const REACTION_REPUTATION_MAP = {
  logical: 'RECEIVE_LOGICAL',
  illogical: 'RECEIVE_ILLOGICAL',
  inspiring: 'RECEIVE_INSPIRING',
  unclear: 'RECEIVE_UNCLEAR',
};

app.post('/api/comments/:id/react', authMiddleware, requireVerifiedEmail, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    }
    
    const reactionType = req.body.type;
    const validReactions = ['logical', 'illogical', 'inspiring', 'unclear'];
    if (!validReactions.includes(reactionType)) {
      return res.status(400).json({ success: false, message: 'نوع التفاعل غير صحيح' });
    }
    
    const comment = await Comment.findById(req.params.id);
    if (!comment) return res.status(404).json({ success: false, message: 'التعليق غير موجود' });
    
    const discussion = await Discussion.findById(comment.discussionId);
    if (discussion && isDiscussionExpired(discussion)) {
      return res.status(403).json({ success: false, message: 'انتهى وقت النقاش' });
    }
    
    if (!comment.reactions) {
      comment.reactions = { logical: [], illogical: [], inspiring: [], unclear: [] };
    }
    validReactions.forEach(t => {
      if (!comment.reactions[t]) comment.reactions[t] = [];
    });
    
    const userId = req.user.userId;
    const currentReactionIndex = comment.reactions[reactionType].indexOf(userId);
    const isAdding = currentReactionIndex === -1;
    
    let removedReactionType = null;
    
    if (isAdding) {
      const userActiveReactions = validReactions.filter(t => 
        comment.reactions[t].includes(userId)
      );
      
      if (userActiveReactions.length >= MAX_REACTIONS_PER_USER) {
        const oldestType = userActiveReactions[0];
        const idx = comment.reactions[oldestType].indexOf(userId);
        if (idx !== -1) {
          comment.reactions[oldestType].splice(idx, 1);
          removedReactionType = oldestType;
          
          if (comment.author._id.toString() !== userId) {
            const oldKey = REACTION_REPUTATION_MAP[oldestType];
            await updateAuthorReputation(comment.author._id, -REPUTATION_REWARDS[oldKey]);
          }
        }
      }
      
      comment.reactions[reactionType].push(userId);
      
      if (comment.author._id.toString() !== userId) {
        const newKey = REACTION_REPUTATION_MAP[reactionType];
        await updateAuthorReputation(comment.author._id, REPUTATION_REWARDS[newKey]);
      }
    } else {
      comment.reactions[reactionType].splice(currentReactionIndex, 1);
      
      if (comment.author._id.toString() !== userId) {
        const removedKey = REACTION_REPUTATION_MAP[reactionType];
        await updateAuthorReputation(comment.author._id, -REPUTATION_REWARDS[removedKey]);
      }
    }
    
    comment.qualityScore = calculateQualityScore(comment);
    comment.markModified('reactions');
    await comment.save();

    if (isAdding && (reactionType === 'logical' || reactionType === 'inspiring') && comment.author && comment.author._id) {
      const sender = await User.findById(userId).select('name avatar').lean();
      const reactionTitles = {
        logical: 'تعليقك وُصف بالمنطقي',
        inspiring: 'تعليقك وُصف بالملهم',
      };
      await createNotification({
        recipient: comment.author._id,
        sender: sender ? { _id: userId, name: sender.name, avatar: sender.avatar } : { _id: userId },
        type: 'reaction_' + reactionType,
        title: reactionTitles[reactionType],
        message: (comment.content || '').slice(0, 200),
        link: '/discussion/' + comment.discussionId.toString() + '#c-' + comment._id.toString(),
        metadata: {
          discussionId: comment.discussionId.toString(),
          commentId: comment._id.toString(),
          reactionType,
        },
      });
    }

    res.json({
      success: true,
      reactionType,
      active: isAdding,
      removedReactionType,
      counts: {
        logical: comment.reactions.logical.length,
        illogical: comment.reactions.illogical.length,
        inspiring: comment.reactions.inspiring.length,
        unclear: comment.reactions.unclear.length,
      },
      qualityScore: comment.qualityScore
    });
  } catch (error) {
    console.error('React to comment error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.delete('/api/comments/:id', authMiddleware, requireVerifiedEmail, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    }
    const comment = await Comment.findById(req.params.id);
    if (!comment) {
      return res.status(404).json({ success: false, message: 'التعليق غير موجود' });
    }
    const userId = req.user.userId;
    const isOwner = comment.author._id.toString() === userId;
    const currentUser = await User.findById(userId);
    const isAdmin = currentUser && (currentUser.role === 'admin' || currentUser.role === 'moderator');
    if (!isOwner && !isAdmin) {
      return res.status(403).json({ success: false, message: 'غير مسموح بحذف هذا التعليق' });
    }
    
    const discussionId = comment.discussionId;
    const stance = comment.stance;
    const isReply = comment.isReply;

    const repliesResult = await Comment.deleteMany({ parentCommentId: comment._id });
    await Comment.findByIdAndDelete(req.params.id);

    const totalDeleted = 1 + (repliesResult.deletedCount || 0);
    
    if (!isReply) {
      const stanceField = `stanceStats.${stance}`;
      await Discussion.findByIdAndUpdate(discussionId, { 
        $inc: { commentCount: -totalDeleted, [stanceField]: -1 } 
      });
    } else {
      await Discussion.findByIdAndUpdate(discussionId, { 
        $inc: { commentCount: -totalDeleted } 
      });
    }
    
    res.json({ success: true, message: 'تم حذف التعليق' });
  } catch (error) {
    console.error('Delete comment error:', error);
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

app.post('/api/circles', authMiddleware, requireVerifiedEmail, async (req, res) => {
  try {
    const name = sanitizeString(req.body.name, 100);
    if (!name || name.length < 3) {
      return res.status(400).json({ success: false, message: 'اسم الدائرة يجب أن يكون 3 أحرف على الأقل' });
    }

    const description = sanitizeString(req.body.description || '', 500);
    const category = sanitizeString(req.body.category || '', 50);
    const isPrivate = req.body.isPrivate === true;

    let icon = typeof req.body.icon === 'string' ? req.body.icon.trim().slice(0, 4) : '';
    if (!icon) icon = '🌐';

    let color = typeof req.body.color === 'string' ? req.body.color.trim() : '';
    if (!/^#[0-9a-fA-F]{6}$/.test(color)) color = '#daa520';

    let tags = [];
    if (Array.isArray(req.body.tags)) {
      tags = req.body.tags
        .filter(t => typeof t === 'string')
        .map(t => sanitizeString(t, 30))
        .filter(t => t.length > 0)
        .slice(0, 10);
    }

    const nameTaken = await Circle.exists({ name });
    if (nameTaken) {
      return res.status(409).json({ success: false, message: 'اسم الدائرة مستخدم بالفعل' });
    }

    const user = await User.findById(req.user.userId).select('name').lean();
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });

    const userId = req.user.userId;
    const circle = await Circle.create({
      name,
      description,
      category: category || undefined,
      isPrivate,
      icon,
      color,
      tags,
      memberIds: [userId],
      members: 1,
      pendingRequests: [],
      discussionCount: 0,
      createdBy: { _id: userId, name: user.name },
    });

    res.status(201).json({
      success: true,
      circle: Object.assign({}, circle.toObject(), { _id: circle._id.toString() }),
    });
  } catch (error) {
    console.error('Create circle error:', error);
    if (error && error.code === 11000) {
      return res.status(409).json({ success: false, message: 'اسم الدائرة مستخدم بالفعل' });
    }
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

app.post('/api/circles/:id/join', authMiddleware, requireVerifiedEmail, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    const circle = await Circle.findById(req.params.id);
    if (!circle) return res.status(404).json({ success: false, message: 'الدائرة غير موجودة' });
    const userId = req.user.userId;
    const user = await User.findById(userId).select('name avatar').lean();
    const memberIndex = circle.memberIds.indexOf(userId);
    
    // If already a member, leave the circle
    if (memberIndex !== -1) {
      circle.memberIds.splice(memberIndex, 1);
      circle.members = Math.max(0, circle.members - 1);
      await circle.save();
      return res.json({ success: true, joined: false, members: circle.members });
    }
    
    // For private circles, add to pendingRequests instead of memberIds
    if (circle.isPrivate) {
      const alreadyPending = circle.pendingRequests.some(r => r.userId === userId);
      if (alreadyPending) {
        return res.json({ success: true, status: 'pending', message: 'طلبك قيد المراجعة' });
      }
      circle.pendingRequests.push({
        userId: userId,
        userName: user ? user.name : 'مستخدم',
        userAvatar: user ? user.avatar : '',
        requestedAt: new Date(),
        message: req.body.message || '',
      });
      await circle.save();

      if (circle.createdBy && circle.createdBy._id && mongoose.Types.ObjectId.isValid(circle.createdBy._id)) {
        await createNotification({
          recipient: circle.createdBy._id,
          sender: { _id: userId, name: user ? user.name : '', avatar: user ? user.avatar : '' },
          type: 'circle_join_request',
          title: 'طلب انضمام جديد لدائرتك',
          message: (user ? user.name : 'مستخدم') + ' يطلب الانضمام إلى ' + circle.name,
          link: '/circles/' + circle._id.toString(),
          metadata: {
            circleId: circle._id.toString(),
            requesterId: userId,
          },
        });
      }

      return res.json({ success: true, status: 'pending', message: 'تم إرسال طلب الانضمام' });
    }
    
    // For public circles, add directly
    circle.memberIds.push(userId);
    circle.members += 1;
    await circle.save();
    res.json({ success: true, joined: true, members: circle.members });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

// Approve a pending request (admin/owner only)
app.post('/api/circles/:id/approve/:userId', authMiddleware, requireVerifiedEmail, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    const circle = await Circle.findById(req.params.id);
    if (!circle) return res.status(404).json({ success: false, message: 'الدائرة غير موجودة' });
    
    // Only admin or circle creator can approve
    const user = await User.findById(req.user.userId);
    const isAdmin = user && (user.role === 'admin' || user.role === 'moderator');
    const isCreator = circle.createdBy && circle.createdBy._id === req.user.userId;
    if (!isAdmin && !isCreator) {
      return res.status(403).json({ success: false, message: 'لا تملك صلاحية الموافقة' });
    }
    
    const pendingIndex = circle.pendingRequests.findIndex(r => r.userId === req.params.userId);
    if (pendingIndex === -1) {
      return res.status(404).json({ success: false, message: 'طلب غير موجود' });
    }
    
    // Move from pending to members
    circle.pendingRequests.splice(pendingIndex, 1);
    if (!circle.memberIds.includes(req.params.userId)) {
      circle.memberIds.push(req.params.userId);
      circle.members += 1;
    }
    await circle.save();

    if (mongoose.Types.ObjectId.isValid(req.params.userId)) {
      await createNotification({
        recipient: req.params.userId,
        sender: { _id: req.user.userId, name: user ? user.name : '', avatar: user ? user.avatar : '' },
        type: 'circle_approved',
        title: 'تمت الموافقة على طلبك',
        message: 'مرحباً بك في ' + circle.name,
        link: '/circles/' + circle._id.toString(),
        metadata: { circleId: circle._id.toString() },
      });
    }

    res.json({ success: true, message: 'تمت الموافقة' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

// Reject a pending request
app.post('/api/circles/:id/reject/:userId', authMiddleware, requireVerifiedEmail, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    const circle = await Circle.findById(req.params.id);
    if (!circle) return res.status(404).json({ success: false, message: 'الدائرة غير موجودة' });
    
    const user = await User.findById(req.user.userId);
    const isAdmin = user && (user.role === 'admin' || user.role === 'moderator');
    const isCreator = circle.createdBy && circle.createdBy._id === req.user.userId;
    if (!isAdmin && !isCreator) {
      return res.status(403).json({ success: false, message: 'لا تملك صلاحية الرفض' });
    }
    
    const pendingIndex = circle.pendingRequests.findIndex(r => r.userId === req.params.userId);
    if (pendingIndex === -1) {
      return res.status(404).json({ success: false, message: 'طلب غير موجود' });
    }

    circle.pendingRequests.splice(pendingIndex, 1);
    await circle.save();

    if (mongoose.Types.ObjectId.isValid(req.params.userId)) {
      await createNotification({
        recipient: req.params.userId,
        sender: { _id: req.user.userId, name: user ? user.name : '', avatar: user ? user.avatar : '' },
        type: 'circle_rejected',
        title: 'تحديث بشأن طلب انضمامك',
        message: 'لم تُقبل طلبك في "' + circle.name + '" حالياً، نتمنى لك مشاركة في دوائر أخرى',
        link: '/circles',
        metadata: { circleId: circle._id.toString() },
      });
    }

    res.json({ success: true, message: 'تم الرفض' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const filter = (req.query.filter || 'all').toString();
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));

    const query = { recipient: req.user.userId };
    if (filter === 'unread') {
      query.isRead = false;
    } else if (filter === 'comment') {
      query.type = { $in: ['comment', 'reply'] };
    } else if (filter === 'reply') {
      query.type = 'reply';
    } else if (filter === 'upvote') {
      query.type = { $in: ['discussion_upvote', 'comment_upvote'] };
    } else if (filter === 'reaction') {
      query.type = { $in: ['reaction_logical', 'reaction_inspiring'] };
    } else if (filter === 'circle') {
      query.type = { $in: ['circle_join_request', 'circle_approved', 'circle_rejected'] };
    }

    const [total, notifications, unreadCount] = await Promise.all([
      Notification.countDocuments(query),
      Notification.find(query)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Notification.countDocuments({ recipient: req.user.userId, isRead: false }),
    ]);

    res.json({
      success: true,
      notifications: notifications.map(n => Object.assign({}, n, {
        _id: n._id.toString(),
        recipient: n.recipient ? n.recipient.toString() : null,
        sender: n.sender ? Object.assign({}, n.sender, {
          _id: n.sender._id ? n.sender._id.toString() : null,
        }) : null,
      })),
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
      unreadCount,
    });
  } catch (error) {
    console.error('List notifications error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/notifications/unread-count', authMiddleware, async (req, res) => {
  try {
    const count = await Notification.countDocuments({ recipient: req.user.userId, isRead: false });
    res.json({ success: true, count });
  } catch (error) {
    console.error('Unread count error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.patch('/api/notifications/read-all', authMiddleware, async (req, res) => {
  try {
    const result = await Notification.updateMany(
      { recipient: req.user.userId, isRead: false },
      { $set: { isRead: true } }
    );
    res.json({ success: true, modifiedCount: result.modifiedCount || 0 });
  } catch (error) {
    console.error('Read-all notifications error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.patch('/api/notifications/:id/read', authMiddleware, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    }
    const notification = await Notification.findById(req.params.id);
    if (!notification) {
      return res.status(404).json({ success: false, message: 'الإشعار غير موجود' });
    }
    if (notification.recipient.toString() !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'غير مصرح' });
    }
    if (!notification.isRead) {
      notification.isRead = true;
      await notification.save();
    }
    res.json({ success: true });
  } catch (error) {
    console.error('Mark notification read error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.delete('/api/notifications/:id', authMiddleware, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    }
    const notification = await Notification.findById(req.params.id);
    if (!notification) {
      return res.status(404).json({ success: false, message: 'الإشعار غير موجود' });
    }
    if (notification.recipient.toString() !== req.user.userId) {
      return res.status(403).json({ success: false, message: 'غير مصرح' });
    }
    await Notification.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete notification error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/users/leaderboard', async (req, res) => {
  try {
    const users = await User.find().sort({ reputation: -1 }).limit(10).select('name avatar reputation role isFoundingMember').lean();
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
    res.json({ success: true, user: Object.assign({}, userToResponse(user), { discussions: userDiscussions, createdAt: user.createdAt }) });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.put('/api/users/profile', authMiddleware, async (req, res) => {
  try {
    const updates = {};

    if (req.body.name !== undefined) {
      const name = sanitizeString(req.body.name, 100);
      if (!name || name.length < 2) {
        return res.status(400).json({ success: false, message: 'الاسم يجب أن يكون حرفين على الأقل' });
      }
      updates.name = name;
    }

    if (req.body.bio !== undefined) {
      updates.bio = sanitizeString(req.body.bio, 500);
    }

    if (req.body.avatar !== undefined) {
      updates.avatar = sanitizeString(req.body.avatar, 500);
    }

    if (req.body.location !== undefined) {
      updates.location = sanitizeString(req.body.location, 100);
    }

    if (req.body.website !== undefined) {
      const website = sanitizeString(req.body.website, 200);
      if (website && !/^https?:\/\/[^\s]+\.[^\s]+/i.test(website)) {
        return res.status(400).json({ success: false, message: 'رابط الموقع غير صحيح - يجب أن يبدأ بـ http:// أو https://' });
      }
      updates.website = website;
    }

    const user = await User.findByIdAndUpdate(req.user.userId, updates, { new: true, runValidators: true });
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    res.json({ success: true, user: userToResponse(user) });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/users/avatar/signature', authMiddleware, async (req, res) => {
  try {
    if (!cloudinaryConfigured()) {
      return res.status(503).json({ success: false, message: 'خدمة رفع الصور غير مفعّلة على الخادم' });
    }
    const timestamp = Math.floor(Date.now() / 1000);
    const publicId = 'user_' + req.user.userId + '_' + timestamp;
    const paramsToSign = 'folder=' + CLOUDINARY_AVATAR_FOLDER + '&public_id=' + publicId + '&timestamp=' + timestamp;
    const signature = crypto.createHash('sha1').update(paramsToSign + CLOUDINARY_API_SECRET).digest('hex');
    res.json({
      success: true,
      signature,
      timestamp,
      apiKey: CLOUDINARY_API_KEY,
      cloudName: CLOUDINARY_CLOUD_NAME,
      folder: CLOUDINARY_AVATAR_FOLDER,
      publicId
    });
  } catch (error) {
    console.error('Avatar signature error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.patch('/api/users/avatar', authMiddleware, async (req, res) => {
  try {
    const raw = (req.body && req.body.avatarUrl !== undefined) ? req.body.avatarUrl : null;
    if (raw === null || raw === '') {
      const user = await User.findByIdAndUpdate(req.user.userId, { avatar: '' }, { new: true });
      if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
      return res.json({ success: true, user: userToResponse(user) });
    }
    const avatarUrl = sanitizeString(raw, 500);
    if (!avatarUrl) {
      return res.status(400).json({ success: false, message: 'رابط الصورة غير صحيح' });
    }
    if (!cloudinaryConfigured()) {
      return res.status(503).json({ success: false, message: 'خدمة رفع الصور غير مفعّلة على الخادم' });
    }
    const expectedHost = 'res.cloudinary.com/' + CLOUDINARY_CLOUD_NAME + '/';
    const isCloudinary = avatarUrl.startsWith('https://' + expectedHost) && avatarUrl.includes('/' + CLOUDINARY_AVATAR_FOLDER + '/');
    if (!isCloudinary) {
      return res.status(400).json({ success: false, message: 'رابط الصورة يجب أن يكون من خدمة الرفع المعتمدة' });
    }
    const user = await User.findByIdAndUpdate(req.user.userId, { avatar: avatarUrl }, { new: true, runValidators: true });
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    res.json({ success: true, user: userToResponse(user) });
  } catch (error) {
    console.error('Update avatar error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.patch('/api/users/change-password', authMiddleware, authLimiter, async (req, res) => {
  try {
    const currentPassword = req.body.currentPassword;
    const newPassword = req.body.newPassword;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, message: 'كلمة المرور الحالية والجديدة مطلوبتان' });
    }
    if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
      return res.status(400).json({ success: false, message: 'بيانات غير صحيحة' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, message: 'كلمة المرور الجديدة يجب أن تكون 8 أحرف على الأقل' });
    }
    if (newPassword.length > 200) {
      return res.status(400).json({ success: false, message: 'كلمة المرور الجديدة طويلة جداً' });
    }
    if (newPassword === currentPassword) {
      return res.status(400).json({ success: false, message: 'كلمة المرور الجديدة لا يمكن أن تطابق الحالية' });
    }

    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });

    if (user.authProvider === 'google') {
      return res.status(403).json({ success: false, message: 'غير متاح للحسابات المُسجَّلة عبر Google' });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'كلمة المرور الحالية غير صحيحة' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.passwordResetTokenHash = null;
    user.passwordResetTokenExpiry = null;
    await user.save();

    res.json({ success: true, message: 'تم تغيير كلمة المرور بنجاح' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.patch('/api/users/notification-preferences', authMiddleware, async (req, res) => {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const dotted = {};

    for (const key of Object.keys(body)) {
      if (!NOTIFICATION_TYPES.includes(key)) continue;
      const value = body[key];
      if (typeof value !== 'boolean') {
        return res.status(400).json({ success: false, message: 'قيمة الإعداد يجب أن تكون true أو false' });
      }
      dotted['notificationPreferences.' + key] = value;
    }

    if (Object.keys(dotted).length === 0) {
      return res.status(400).json({ success: false, message: 'لم يتم تمرير أي إعداد صالح' });
    }

    const user = await User.findByIdAndUpdate(
      req.user.userId,
      { $set: dotted },
      { new: true, runValidators: true }
    );
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });

    res.json({ success: true, user: userToResponse(user) });
  } catch (error) {
    console.error('Update notification preferences error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

const RESERVED_USERNAMES = new Set([
  'admin', 'administrator', 'root', 'api', 'auth', 'me', 'login', 'register',
  'logout', 'signin', 'signup', 'settings', 'profile', 'profiles', 'user',
  'users', 'discussion', 'discussions', 'circle', 'circles', 'notification',
  'notifications', 'search', 'home', 'feed', 'about', 'help', 'support',
  'terms', 'privacy', 'contact', 'aporialab', 'aporia',
]);

function validateUsernameShape(raw) {
  if (typeof raw !== 'string') return { ok: false, message: 'اسم المستخدم غير صحيح' };
  const value = raw.trim().toLowerCase();
  if (!USERNAME_PATTERN.test(value)) {
    return { ok: false, message: 'اسم المستخدم يجب أن يكون 3-30 حرفاً ويحتوي فقط على حروف إنجليزية صغيرة وأرقام وشرطة سفلية' };
  }
  if (RESERVED_USERNAMES.has(value)) {
    return { ok: false, message: 'اسم المستخدم محجوز' };
  }
  return { ok: true, value };
}

app.get('/api/users/check-username', async (req, res) => {
  try {
    const raw = (req.query.username || '').toString();
    const check = validateUsernameShape(raw);
    if (!check.ok) {
      return res.json({ success: true, available: false, reason: check.message });
    }
    const taken = await User.exists({ username: check.value });
    res.json({ success: true, available: !taken, username: check.value });
  } catch (error) {
    console.error('check-username error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.patch('/api/users/username', authMiddleware, async (req, res) => {
  try {
    const check = validateUsernameShape(req.body && req.body.username);
    if (!check.ok) {
      return res.status(400).json({ success: false, message: check.message });
    }
    const me = await User.findById(req.user.userId);
    if (!me) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    if (me.username === check.value) {
      return res.json({ success: true, user: userToResponse(me) });
    }
    const taken = await User.exists({ username: check.value, _id: { $ne: me._id } });
    if (taken) {
      return res.status(409).json({ success: false, message: 'اسم المستخدم مستخدم بالفعل' });
    }
    me.username = check.value;
    try {
      await me.save();
    } catch (err) {
      if (err && err.code === 11000) {
        return res.status(409).json({ success: false, message: 'اسم المستخدم مستخدم بالفعل' });
      }
      throw err;
    }
    res.json({ success: true, user: userToResponse(me) });
  } catch (error) {
    console.error('Update username error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/users/:id', async (req, res) => {
  try {
    const param = req.params.id;
    let user;
    if (mongoose.Types.ObjectId.isValid(param) && param.length === 24) {
      user = await User.findById(param).select('-password').lean();
    }
    if (!user && USERNAME_PATTERN.test(param.toLowerCase())) {
      user = await User.findOne({ username: param.toLowerCase() }).select('-password').lean();
    }
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });

    const discussions = await Discussion.find({ 'author._id': user._id })
      .sort({ createdAt: -1 })
      .limit(20)
      .lean();

    const discussionCount = await Discussion.countDocuments({ 'author._id': user._id });

    res.json({
      success: true,
      user: {
        id: user._id.toString(),
        _id: user._id.toString(),
        username: user.username || null,
        name: user.name,
        avatar: user.avatar,
        bio: user.bio,
        location: user.location || '',
        website: user.website || '',
        reputation: user.reputation,
        role: user.role,
        isFoundingMember: user.isFoundingMember,
        discussionCount,
        createdAt: user.createdAt
      },
      discussions: discussions.map(d => Object.assign({}, d, {
        _id: d._id.toString(),
        isExpired: isDiscussionExpired(d)
      }))
    });
  } catch (error) {
    console.error('Get user by id error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/search', async (req, res) => {
  try {
    const q = (req.query.q || '').toString().trim();
    
    if (!q || q.length < 2) {
      return res.json({ 
        success: true, 
        discussions: [], 
        users: [],
        message: 'اكتب حرفين على الأقل للبحث'
      });
    }
    
    const searchRegex = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    
    const [discussions, users] = await Promise.all([
      Discussion.find({
        $or: [
          { title: searchRegex },
          { content: searchRegex },
          { tags: searchRegex }
        ]
      })
        .sort({ views: -1, createdAt: -1 })
        .limit(20)
        .lean(),
      
      User.find({
        $or: [
          { name: searchRegex },
          { bio: searchRegex }
        ]
      })
        .select('name avatar bio reputation role isFoundingMember')
        .sort({ reputation: -1 })
        .limit(10)
        .lean()
    ]);
    
    res.json({
      success: true,
      query: q,
      discussions: discussions.map(d => Object.assign({}, d, { 
        _id: d._id.toString(),
        isExpired: isDiscussionExpired(d)
      })),
      users: users.map(u => Object.assign({}, u, { id: u._id.toString(), _id: u._id.toString() }))
    });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ success: false, message: 'خطأ في البحث' });
  }
});
// Delete legacy/test circles (admin only)
app.post('/api/admin/cleanup-circles', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    // Delete circles with non-emoji icons (legacy data)
    const legacyIcons = ['Brain', 'Scale', 'Cpu', 'TrendingUp', 'Heart', 'BookOpen', 'Lightbulb', 'Globe2'];
    const result = await Circle.deleteMany({
      icon: { $in: legacyIcons }
    });

    res.json({
      success: true,
      deletedCount: result.deletedCount,
      message: `تم حذف ${result.deletedCount} دائرة قديمة`
    });
  } catch (error) {
    console.error('Cleanup error:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});
app.post('/api/admin/seed-circles', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const CIRCLES_DATA = [
      {
        name: 'الفلسفة الإغريقية',
        description: 'دراسة فلاسفة اليونان: سقراط، أفلاطون، أرسطو، والحكماء قبلهم',
        category: 'philosophy',
        icon: '🏛️',
        color: '#3b82f6',
        bannerColor: 'from-blue-500/20 to-blue-700/10',
        tags: ['سقراط', 'أفلاطون', 'أرسطو', 'فلسفة قديمة'],
        isPrivate: false,
      },
      {
        name: 'الفلسفة الإسلامية',
        description: 'تراث الكندي والفارابي وابن سينا وابن رشد والغزالي',
        category: 'philosophy',
        icon: '🌙',
        color: '#10b981',
        bannerColor: 'from-emerald-500/20 to-emerald-700/10',
        tags: ['ابن رشد', 'ابن سينا', 'الفارابي', 'الغزالي'],
        isPrivate: false,
      },
      {
        name: 'فلسفة العقل',
        description: 'الوعي، الإدراك، الذكاء الاصطناعي، وطبيعة الفكر',
        category: 'philosophy',
        icon: '🧠',
        color: '#8b5cf6',
        bannerColor: 'from-purple-500/20 to-purple-700/10',
        tags: ['وعي', 'ذكاء اصطناعي', 'إدراك', 'علم النفس'],
        isPrivate: false,
      },
      {
        name: 'الأخلاق المعاصرة',
        description: 'الأخلاق التطبيقية، البيوإثيقا، أخلاقيات التكنولوجيا',
        category: 'ethics',
        icon: '⚖️',
        color: '#f59e0b',
        bannerColor: 'from-amber-500/20 to-amber-700/10',
        tags: ['أخلاق', 'بيوإثيقا', 'تكنولوجيا', 'مجتمع'],
        isPrivate: false,
      },
      {
        name: 'فلسفة السياسة',
        description: 'العدالة، الحرية، الديمقراطية، والنظم السياسية',
        category: 'politics',
        icon: '🌍',
        color: '#ef4444',
        bannerColor: 'from-red-500/20 to-red-700/10',
        tags: ['عدالة', 'حرية', 'ديمقراطية', 'دولة'],
        isPrivate: false,
      },
      {
        name: 'فلسفة العلم',
        description: 'المنهج العلمي، الإبستمولوجيا، تاريخ العلوم',
        category: 'science',
        icon: '🔬',
        color: '#06b6d4',
        bannerColor: 'from-cyan-500/20 to-cyan-700/10',
        tags: ['علم', 'منهج', 'إبستمولوجيا', 'معرفة'],
        isPrivate: false,
      },
      {
        name: 'فلسفة الفن والجمال',
        description: 'الإستطيقا، النقد الفني، فلسفة الإبداع',
        category: 'aesthetics',
        icon: '🎨',
        color: '#ec4899',
        bannerColor: 'from-pink-500/20 to-pink-700/10',
        tags: ['فن', 'جمال', 'إبداع', 'نقد'],
        isPrivate: false,
      },
      {
        name: 'الوجودية والحياة',
        description: 'كيركغارد، نيتشه، سارتر، كامو، ومعنى الوجود',
        category: 'existentialism',
        icon: '🕊️',
        color: '#64748b',
        bannerColor: 'from-slate-500/20 to-slate-700/10',
        tags: ['وجودية', 'نيتشه', 'سارتر', 'معنى'],
        isPrivate: false,
      },
    ];
    
    const results = { created: [], existed: [] };
    
    for (const circleData of CIRCLES_DATA) {
      const existing = await Circle.findOne({ name: circleData.name });
      if (existing) {
        results.existed.push(circleData.name);
      } else {
        const newCircle = new Circle({
          ...circleData,
          members: 0,
          memberIds: [],
          pendingRequests: [],
          discussionCount: 0,
          createdBy: { _id: 'system', name: 'AporiaLab' },
        });
        await newCircle.save();
        results.created.push(circleData.name);
      }
    }
    
    res.json({ success: true, results });
  } catch (error) {
    console.error('Seed circles error:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/admin/reset-founders', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const foundingPhilosophers = [
      { name: 'Ibn Rushd', email: 'ibn.rushd@aporialab.space', bio: 'Andalusian philosopher (Averroes). Commentator on Aristotle. Champion of rationalism.', reputation: 300, role: 'moderator', seed: 'ibnrushd' },
      { name: 'Al-Kindi', email: 'alkindi@aporialab.space', bio: 'First of the Arab philosophers. Pioneer in philosophy of science, mathematics, and cryptography.', reputation: 250, role: 'user', seed: 'alkindi' },
      { name: 'Hypatia', email: 'hypatia@aporialab.space', bio: 'Hellenistic philosopher, astronomer, and mathematician of Alexandria. Symbol of reason and inquiry.', reputation: 220, role: 'user', seed: 'hypatia' },
      { name: 'Avicenna', email: 'avicenna@aporialab.space', bio: 'Ibn Sina. Father of early modern medicine. Philosopher of metaphysics and consciousness.', reputation: 200, role: 'user', seed: 'avicenna' },
      { name: 'Socrates', email: 'socrates@aporialab.space', bio: 'The Athenian gadfly. Father of Western philosophy. "I know that I know nothing."', reputation: 180, role: 'user', seed: 'socrates' }
    ];

    let created = 0;
    let updated = 0;

    for (const p of foundingPhilosophers) {
      const hashedPassword = await bcrypt.hash('AporiaLab2026!Founder', 10);
      const avatarUrl = 'https://api.dicebear.com/7.x/avataaars/svg?seed=' + p.seed;
      
      const existing = await User.findOne({ email: p.email });
      if (existing) {
        await User.findByIdAndUpdate(existing._id, {
          name: p.name, bio: p.bio, reputation: p.reputation,
          role: p.role, avatar: avatarUrl, isFoundingMember: true
        });
        updated++;
      } else {
        await User.create({
          name: p.name, email: p.email, password: hashedPassword,
          authProvider: 'local', emailVerified: true,
          bio: p.bio, reputation: p.reputation, role: p.role,
          avatar: avatarUrl, isFoundingMember: true
        });
        created++;
      }
    }

    res.json({ success: true, message: 'تم تحديث المفكرين المؤسسين', created, updated });
  } catch (error) {
    console.error('Reset founders error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم', error: error.message });
  }
});

app.post('/api/admin/cleanup-non-founders', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const nonFounders = await User.find({ isFoundingMember: { $ne: true } }).select('_id name email');
    const userIds = nonFounders.map(u => u._id);
    const userInfo = nonFounders.map(u => ({ name: u.name, email: u.email }));

    if (userIds.length === 0) {
      return res.json({ success: true, message: 'لا يوجد مستخدمين للحذف', deletedUsers: 0 });
    }

    const deletedDiscussions = await Discussion.deleteMany({ 'author._id': { $in: userIds } });
    const deletedComments = await Comment.deleteMany({ 'author._id': { $in: userIds } });
    const deletedUsers = await User.deleteMany({ _id: { $in: userIds } });

    res.json({
      success: true, message: 'تم حذف كل المستخدمين غير المؤسسين',
      deletedUsers: deletedUsers.deletedCount || 0,
      deletedNames: userInfo,
      deletedDiscussions: deletedDiscussions.deletedCount || 0,
      deletedComments: deletedComments.deletedCount || 0
    });
  } catch (error) {
    console.error('Cleanup error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم', error: error.message });
  }
});

app.use((req, res) => res.status(404).json({ success: false, message: 'المسار ' + req.path + ' غير موجود' }));
app.use((err, req, res, next) => {
  if (err.message === 'Not allowed by CORS') return res.status(403).json({ success: false, message: 'غير مسموح' });
  console.error(err.stack);
  res.status(500).json({ success: false, message: 'خطأ داخلي في الخادم' });
});

module.exports = app;
