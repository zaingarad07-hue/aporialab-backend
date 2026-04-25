const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const { OAuth2Client } = require('google-auth-library');

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

const googleAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'الكثير من محاولات تسجيل الدخول. حاول بعد 15 دقيقة.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});

app.use('/api/', generalLimiter);

const JWT_SECRET = process.env.JWT_SECRET || 'aporialab-secret-key-2026';
const MONGODB_URI = process.env.MONGODB_URI;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

const VALID_DURATIONS = {
  '12h': 12 * 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '3d': 3 * 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
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

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 200 },
  password: { type: String, default: '' },
  googleId: { type: String, default: null, sparse: true, index: true },
  authProvider: { type: String, enum: ['local', 'google'], default: 'local' },
  emailVerified: { type: Boolean, default: false },
  avatar: { type: String, default: '' },
  bio: { type: String, default: '', maxlength: 500 },
  reputation: { type: Number, default: 0 },
  role: { type: String, enum: ['user', 'moderator', 'admin'], default: 'user' },
  isFoundingMember: { type: Boolean, default: false },
}, { timestamps: true });

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
    evidenced: [{ type: String }],
    insightful: [{ type: String }],
    clarify: [{ type: String }],
  },
  qualityScore: { type: Number, default: 0 },
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

function isDiscussionExpired(discussion) {
  if (!discussion.expiresAt) return false;
  return new Date() > new Date(discussion.expiresAt);
}

function calculateQualityScore(comment) {
  const upvotes = (comment.upvotes || []).length;
  const logical = (comment.reactions?.logical || []).length;
  const evidenced = (comment.reactions?.evidenced || []).length;
  const insightful = (comment.reactions?.insightful || []).length;
  const clarify = (comment.reactions?.clarify || []).length;
  
  const positive = upvotes * 3 + logical * 2 + evidenced * 2 + insightful * 1.5;
  const negative = clarify * 0.5;
  
  return Math.max(0, Math.round(positive - negative));
}

function userToResponse(user) {
  return {
    id: user._id.toString(),
    _id: user._id.toString(),
    name: user.name,
    email: user.email,
    avatar: user.avatar,
    bio: user.bio,
    reputation: user.reputation,
    role: user.role,
    isFoundingMember: user.isFoundingMember,
    authProvider: user.authProvider,
    emailVerified: user.emailVerified
  };
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

app.get('/', (req, res) => res.json({ name: 'AporiaLab API', version: '3.9.0', status: 'running', database: 'MongoDB', security: 'enhanced', auth: 'local + google', features: 'stances + reactions + timer' }));

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
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ success: false, message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
    if (user.authProvider === 'google' && !user.password) {
      return res.status(401).json({ success: false, message: 'هذا الحساب يُسجّل الدخول بـ Google' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ success: false, message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
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
    const newUser = await User.create({
      name, email, password: hashedPassword,
      authProvider: 'local',
      emailVerified: false,
      avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=' + encodeURIComponent(email),
      bio: '', reputation: 0, role: 'user', isFoundingMember: false
    });
    const token = jwt.sign({ userId: newUser._id.toString(), email: newUser.email }, JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({ success: true, token, user: userToResponse(newUser) });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
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
    
    const comments = await Comment.find({ discussionId: req.params.id })
      .sort({ qualityScore: -1, createdAt: -1 })
      .lean();
    
    const enrichedComments = comments.map(c => ({
      ...c,
      _id: c._id.toString(),
      reactions: {
        logical: c.reactions?.logical || [],
        evidenced: c.reactions?.evidenced || [],
        insightful: c.reactions?.insightful || [],
        clarify: c.reactions?.clarify || [],
      }
    }));
    
    res.json({ 
      success: true, 
      discussion: Object.assign({}, discussion, { 
        _id: discussion._id.toString(), 
        comments: enrichedComments,
        isExpired: isDiscussionExpired(discussion)
      }) 
    });
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
      stanceStats: { pro: 0, con: 0, neutral: 0 }
    });
    await User.findByIdAndUpdate(user._id, { $inc: { reputation: 10 } });
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

app.post('/api/discussions/:id/like', authMiddleware, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    const discussion = await Discussion.findById(req.params.id);
    if (!discussion) return res.status(404).json({ success: false, message: 'النقاش غير موجود' });
    if (isDiscussionExpired(discussion)) return res.status(403).json({ success: false, message: 'انتهى وقت النقاش' });
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
    if (isDiscussionExpired(discussion)) return res.status(403).json({ success: false, message: 'انتهى وقت النقاش - لا يمكن إضافة تعليقات جديدة' });
    
    const content = sanitizeString(req.body.content, 5000);
    const stance = req.body.stance;
    
    if (!content) return res.status(400).json({ success: false, message: 'محتوى التعليق مطلوب' });
    if (!['pro', 'con', 'neutral'].includes(stance)) {
      return res.status(400).json({ success: false, message: 'يجب اختيار موقف (مع/ضد/محايد)' });
    }
    
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    
    const newComment = await Comment.create({
      discussionId: req.params.id, 
      content,
      stance,
      author: { 
        _id: user._id, 
        name: user.name, 
        avatar: user.avatar, 
        reputation: user.reputation,
        isFoundingMember: user.isFoundingMember
      },
      reactions: {
        logical: [],
        evidenced: [],
        insightful: [],
        clarify: [],
      },
      qualityScore: 0
    });
    
    const stanceField = `stanceStats.${stance}`;
    await Discussion.findByIdAndUpdate(req.params.id, { 
      $inc: { commentCount: 1, [stanceField]: 1 } 
    });
    
    res.status(201).json({ 
      success: true, 
      comment: Object.assign({}, newComment.toObject(), { _id: newComment._id.toString() }) 
    });
  } catch (error) {
    console.error('Add comment error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/comments/:id/upvote', authMiddleware, async (req, res) => {
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
    
    if (upvoteIndex === -1) {
      comment.upvotes.push(userId);
    } else {
      comment.upvotes.splice(upvoteIndex, 1);
    }
    
    comment.qualityScore = calculateQualityScore(comment);
    await comment.save();
    
    res.json({ 
      success: true, 
      upvoted: upvoteIndex === -1, 
      upvotesCount: comment.upvotes.length,
      qualityScore: comment.qualityScore
    });
  } catch (error) {
    console.error('Upvote comment error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/comments/:id/react', authMiddleware, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    }
    
    const reactionType = req.body.type;
    const validReactions = ['logical', 'evidenced', 'insightful', 'clarify'];
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
      comment.reactions = { logical: [], evidenced: [], insightful: [], clarify: [] };
    }
    if (!comment.reactions[reactionType]) {
      comment.reactions[reactionType] = [];
    }
    
    const userId = req.user.userId;
    const reactionIndex = comment.reactions[reactionType].indexOf(userId);
    
    if (reactionIndex === -1) {
      comment.reactions[reactionType].push(userId);
    } else {
      comment.reactions[reactionType].splice(reactionIndex, 1);
    }
    
    comment.qualityScore = calculateQualityScore(comment);
    comment.markModified('reactions');
    await comment.save();
    
    res.json({ 
      success: true, 
      reactionType,
      active: reactionIndex === -1,
      counts: {
        logical: comment.reactions.logical.length,
        evidenced: comment.reactions.evidenced.length,
        insightful: comment.reactions.insightful.length,
        clarify: comment.reactions.clarify.length,
      },
      qualityScore: comment.qualityScore
    });
  } catch (error) {
    console.error('React to comment error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.delete('/api/comments/:id', authMiddleware, async (req, res) => {
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
    const stanceField = `stanceStats.${stance}`;
    
    await Comment.findByIdAndDelete(req.params.id);
    await Discussion.findByIdAndUpdate(discussionId, { 
      $inc: { commentCount: -1, [stanceField]: -1 } 
    });
    
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
    if (req.body.name !== undefined) updates.name = sanitizeString(req.body.name, 100);
    if (req.body.bio !== undefined) updates.bio = sanitizeString(req.body.bio, 500);
    if (req.body.avatar !== undefined) updates.avatar = sanitizeString(req.body.avatar, 500);
    const user = await User.findByIdAndUpdate(req.user.userId, updates, { new: true });
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    res.json({ success: true, user: userToResponse(user) });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/users/:id', async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ success: false, message: 'معرف غير صحيح' });
    }
    const user = await User.findById(req.params.id).select('-password').lean();
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
        name: user.name,
        avatar: user.avatar,
        bio: user.bio,
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

app.get('/api/admin/reset-founders', async (req, res) => {
  try {
    const key = req.query.key || '';
    if (key !== 'aporialab2026') {
      return res.status(403).json({ success: false, message: 'غير مصرح' });
    }

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

app.get('/api/admin/cleanup-non-founders', async (req, res) => {
  try {
    const key = req.query.key || '';
    if (key !== 'aporialab2026') {
      return res.status(403).json({ success: false, message: 'غير مصرح' });
    }

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
