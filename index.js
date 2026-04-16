/**
 * AporiaLab Backend API v3.0
 * 
 * Features:
 * - MongoDB Atlas integration
 * - bcrypt password hashing
 * - Auto-seeding on first run
 * - Connection pooling for serverless
 */

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

const app = express();

// ===== CORS =====
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: false
}));
app.options('*', cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ===== ENV =====
const JWT_SECRET = process.env.JWT_SECRET || 'aporialab-secret-key-2026';
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI environment variable is missing!');
}

// ===== MONGOOSE CONNECTION (Serverless-optimized) =====
let cachedConnection = null;

async function connectDB() {
  if (cachedConnection && mongoose.connection.readyState === 1) {
    return cachedConnection;
  }
  
  if (!MONGODB_URI) {
    throw new Error('MONGODB_URI not configured');
  }
  
  try {
    cachedConnection = await mongoose.connect(MONGODB_URI, {
      bufferCommands: false,
      serverSelectionTimeoutMS: 10000,
    });
    console.log('✅ MongoDB connected');
    return cachedConnection;
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    cachedConnection = null;
    throw error;
  }
}

// ===== SCHEMAS =====
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true }, // hashed
  avatar: { type: String, default: '' },
  bio: { type: String, default: '' },
  reputation: { type: Number, default: 0 },
  role: { type: String, enum: ['user', 'moderator', 'admin'], default: 'user' },
}, { timestamps: true });

const DiscussionSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  content: { type: String, required: true },
  category: { type: String, enum: ['beginner', 'intermediate', 'advanced'], default: 'beginner' },
  tags: [{ type: String }],
  author: {
    _id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String,
    avatar: String,
    reputation: Number
  },
  views: { type: Number, default: 0 },
  upvotes: [{ type: String }],
  commentCount: { type: Number, default: 0 },
}, { timestamps: true });

const CommentSchema = new mongoose.Schema({
  discussionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Discussion', required: true },
  content: { type: String, required: true },
  author: {
    _id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String,
    avatar: String,
    reputation: Number
  },
  upvotes: [{ type: String }],
}, { timestamps: true });

const CircleSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  category: String,
  members: { type: Number, default: 0 },
  isPrivate: { type: Boolean, default: false },
  icon: String,
  color: String,
  memberIds: [{ type: String }],
}, { timestamps: true });

// Models (guard against re-compilation in serverless)
const User = mongoose.models.User || mongoose.model('User', UserSchema);
const Discussion = mongoose.models.Discussion || mongoose.model('Discussion', DiscussionSchema);
const Comment = mongoose.models.Comment || mongoose.model('Comment', CommentSchema);
const Circle = mongoose.models.Circle || mongoose.model('Circle', CircleSchema);

// ===== SEED DATA =====
async function seedIfEmpty() {
  try {
    const userCount = await User.countDocuments();
    if (userCount > 0) return { seeded: false, users: userCount };

    console.log('🌱 Seeding database...');

    const passwordHash = await bcrypt.hash('password123', 10);

    const seedUsers = [
      { name: 'أحمد الفيصل', email: 'ahmed@aporialab.space', password: passwordHash, avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=ahmed', bio: 'مهتم بالفلسفة والنقاش العقلاني', reputation: 150, role: 'user' },
      { name: 'سارة محمد', email: 'sara@aporialab.space', password: passwordHash, avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=sara', bio: 'باحثة اجتماعية ومهتمة بحقوق الإنسان', reputation: 200, role: 'user' },
      { name: 'خالد العمري', email: 'khaled@aporialab.space', password: passwordHash, avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=khaled', bio: 'مهتم بالسياسة والشأن العام', reputation: 180, role: 'user' },
      { name: 'نورة السعيد', email: 'noura@aporialab.space', password: passwordHash, avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=noura', bio: 'أستاذة فلسفة في الجامعة', reputation: 300, role: 'moderator' },
      { name: 'فهد الراشد', email: 'fahd@aporialab.space', password: passwordHash, avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=fahd', bio: 'محلل سياسي وكاتب رأي', reputation: 120, role: 'user' }
    ];

    const createdUsers = await User.insertMany(seedUsers);

    // Map for author data
    const noura = createdUsers.find(u => u.email === 'noura@aporialab.space');
    const sara = createdUsers.find(u => u.email === 'sara@aporialab.space');
    const ahmed = createdUsers.find(u => u.email === 'ahmed@aporialab.space');
    const khaled = createdUsers.find(u => u.email === 'khaled@aporialab.space');
    const fahd = createdUsers.find(u => u.email === 'fahd@aporialab.space');

    const seedDiscussions = [
      {
        title: 'هل الديمقراطية النظام الأمثل للحكم في العالم العربي؟',
        content: 'نقاش مفتوح حول إمكانية تطبيق الديمقراطية في السياق العربي مع مراعاة الخصوصية الثقافية والدينية والتاريخية',
        category: 'advanced',
        tags: ['سياسة', 'ديمقراطية', 'حوكمة'],
        author: { _id: noura._id, name: noura.name, avatar: noura.avatar, reputation: noura.reputation },
        views: 1240,
        upvotes: [ahmed._id.toString(), sara._id.toString(), khaled._id.toString()],
        commentCount: 47,
      },
      {
        title: 'الذكاء الاصطناعي والأخلاق: أين نضع الحدود؟',
        content: 'مع تسارع تطور الذكاء الاصطناعي، كيف نضمن أنه يخدم الإنسانية دون أن يهدد قيمنا وحقوقنا الأساسية؟',
        category: 'intermediate',
        tags: ['تكنولوجيا', 'أخلاق', 'ذكاء اصطناعي'],
        author: { _id: sara._id, name: sara.name, avatar: sara.avatar, reputation: sara.reputation },
        views: 892,
        upvotes: [ahmed._id.toString(), noura._id.toString()],
        commentCount: 33,
      },
      {
        title: 'هل التعليم التقليدي كافٍ في عصر المعلومات؟',
        content: 'مناقشة جدية حول مدى ملاءمة مناهج التعليم الحالية لمتطلبات سوق العمل والحياة في القرن الحادي والعشرين',
        category: 'beginner',
        tags: ['تعليم', 'مستقبل', 'شباب'],
        author: { _id: ahmed._id, name: ahmed.name, avatar: ahmed.avatar, reputation: ahmed.reputation },
        views: 654,
        upvotes: [sara._id.toString(), khaled._id.toString(), fahd._id.toString()],
        commentCount: 28,
      },
      {
        title: 'الهوية الثقافية في زمن العولمة',
        content: 'كيف نحافظ على هويتنا وموروثنا الثقافي في ظل موجة العولمة المتسارعة وانفتاح العالم؟',
        category: 'advanced',
        tags: ['ثقافة', 'هوية', 'عولمة'],
        author: { _id: khaled._id, name: khaled.name, avatar: khaled.avatar, reputation: khaled.reputation },
        views: 445,
        upvotes: [ahmed._id.toString()],
        commentCount: 19,
      },
      {
        title: 'أزمة المناخ: مسؤولية الأفراد أم الحكومات؟',
        content: 'نقاش حول توزيع المسؤولية في مواجهة التغير المناخي بين المواطن العادي والجهات الحكومية والشركات الكبرى',
        category: 'intermediate',
        tags: ['بيئة', 'مناخ', 'سياسة'],
        author: { _id: fahd._id, name: fahd.name, avatar: fahd.avatar, reputation: fahd.reputation },
        views: 387,
        upvotes: [sara._id.toString(), noura._id.toString()],
        commentCount: 15,
      },
      {
        title: 'حرية التعبير: متى تصبح خطراً على المجتمع؟',
        content: 'هل لحرية التعبير حدود يجب احترامها؟ وأين يقع الخط الفاصل بين الرأي الحر والخطاب الضار؟',
        category: 'advanced',
        tags: ['حرية', 'قانون', 'مجتمع'],
        author: { _id: noura._id, name: noura.name, avatar: noura.avatar, reputation: noura.reputation },
        views: 312,
        upvotes: [ahmed._id.toString(), khaled._id.toString(), fahd._id.toString()],
        commentCount: 41,
      }
    ];
    await Discussion.insertMany(seedDiscussions);

    const seedCircles = [
      { name: 'دائرة الفلسفة والأخلاق', description: 'نقاشات عميقة في الفلسفة الأخلاقية وقضايا الوجود والمعرفة', category: 'فلسفة', members: 1240, isPrivate: false, icon: 'Brain', color: 'from-purple-500/20 to-blue-500/20', memberIds: [] },
      { name: 'دائرة الشؤون السياسية', description: 'تحليل الأحداث السياسية والسياسات العامة بموضوعية وعمق', category: 'سياسة', members: 876, isPrivate: false, icon: 'Scale', color: 'from-blue-500/20 to-cyan-500/20', memberIds: [] },
      { name: 'دائرة التكنولوجيا والمجتمع', description: 'فهم التأثيرات الاجتماعية للتكنولوجيا الحديثة والذكاء الاصطناعي', category: 'تكنولوجيا', members: 654, isPrivate: false, icon: 'Cpu', color: 'from-green-500/20 to-emerald-500/20', memberIds: [] },
      { name: 'دائرة الاقتصاد والتنمية', description: 'نقاشات حول التحديات الاقتصادية وسبل التنمية المستدامة', category: 'اقتصاد', members: 432, isPrivate: false, icon: 'TrendingUp', color: 'from-orange-500/20 to-yellow-500/20', memberIds: [] }
    ];
    await Circle.insertMany(seedCircles);

    console.log('✅ Seeding complete');
    return { seeded: true, users: createdUsers.length };
  } catch (error) {
    console.error('❌ Seed error:', error.message);
    return { seeded: false, error: error.message };
  }
}

// ===== MIDDLEWARE =====
// Connect to DB before each request (serverless pattern)
app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (error) {
    res.status(503).json({ success: false, message: 'خطأ في الاتصال بقاعدة البيانات' });
  }
});

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'غير مصرح - يرجى تسجيل الدخول' });
  }
  try {
    const token = authHeader.split(' ')[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'جلسة منتهية - يرجى تسجيل الدخول مجدداً' });
  }
}

// ===== ROUTES =====
app.get('/', (req, res) => {
  res.json({ name: 'AporiaLab API', version: '3.0.0', status: 'running', database: 'MongoDB', timestamp: new Date().toISOString() });
});

app.get('/api/health', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const discussionCount = await Discussion.countDocuments();
    res.json({
      status: 'OK',
      timestamp: new Date().toISOString(),
      database: 'connected',
      users: userCount,
      discussions: discussionCount
    });
  } catch (error) {
    res.status(500).json({ status: 'ERROR', message: error.message });
  }
});

// Manual seed endpoint (for first-time setup)
app.get('/api/seed', async (req, res) => {
  if (req.query.key !== 'aporialab2026') {
    return res.status(401).json({ success: false, message: 'Invalid key' });
  }
  const result = await seedIfEmpty();
  res.json({ success: true, ...result });
});

// ===== AUTH =====
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'البريد الإلكتروني وكلمة المرور مطلوبان' });

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(401).json({ success: false, message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ success: false, message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });

    const token = jwt.sign({ userId: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      success: true, token,
      user: { id: user._id.toString(), _id: user._id.toString(), name: user.name, email: user.email, avatar: user.avatar, bio: user.bio, reputation: user.reputation, role: user.role }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ success: false, message: 'جميع الحقول مطلوبة' });
    if (password.length < 6) return res.status(400).json({ success: false, message: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });

    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) return res.status(400).json({ success: false, message: 'هذا البريد الإلكتروني مسجل مسبقاً' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      avatar: `https://api.dicebear.com/7.x/avataaars/svg?seed=${encodeURIComponent(email)}`,
      bio: '',
      reputation: 0,
      role: 'user'
    });

    const token = jwt.sign({ userId: newUser._id.toString(), email: newUser.email }, JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({
      success: true, token,
      user: { id: newUser._id.toString(), _id: newUser._id.toString(), name: newUser.name, email: newUser.email, avatar: newUser.avatar, bio: newUser.bio, reputation: newUser.reputation, role: newUser.role }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    res.json({
      success: true,
      user: { id: user._id.toString(), _id: user._id.toString(), name: user.name, email: user.email, avatar: user.avatar, bio: user.bio, reputation: user.reputation, role: user.role }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

// ===== DISCUSSIONS =====
app.get('/api/discussions', async (req, res) => {
  try {
    const { sort = 'trending', filter, level, page = 1, limit = 10 } = req.query;
    const query = {};
    if (level && level !== 'all') query.category = level;
    if (filter && filter !== 'all') query.category = filter;

    let sortObj = {};
    if (sort === 'trending') sortObj = { views: -1, createdAt: -1 };
    else if (sort === 'featured') sortObj = { upvotes: -1 };
    else if (sort === 'live') sortObj = { commentCount: -1 };
    else sortObj = { createdAt: -1 };

    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const total = await Discussion.countDocuments(query);
    const discussions = await Discussion.find(query).sort(sortObj).skip((pageNum - 1) * limitNum).limit(limitNum).lean();

    res.json({
      success: true,
      discussions: discussions.map(d => ({ ...d, _id: d._id.toString() })),
      pagination: { page: pageNum, pages: Math.ceil(total / limitNum), total }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/discussions/:id', async (req, res) => {
  try {
    const discussion = await Discussion.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } }, { new: true }).lean();
    if (!discussion) return res.status(404).json({ success: false, message: 'النقاش غير موجود' });
    const comments = await Comment.find({ discussionId: req.params.id }).sort({ createdAt: -1 }).lean();
    res.json({ success: true, discussion: { ...discussion, _id: discussion._id.toString(), comments } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/discussions', authMiddleware, async (req, res) => {
  try {
    const { title, description, content, level, tags } = req.body;
    if (!title || !content) return res.status(400).json({ success: false, message: 'العنوان والمحتوى مطلوبان' });

    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });

    const newDiscussion = await Discussion.create({
      title: title.trim(),
      content: (content || description || '').trim(),
      category: level || 'beginner',
      tags: tags || [],
      author: { _id: user._id, name: user.name, avatar: user.avatar, reputation: user.reputation }
    });

    await User.findByIdAndUpdate(user._id, { $inc: { reputation: 10 } });

    res.status(201).json({ success: true, discussion: { ...newDiscussion.toObject(), _id: newDiscussion._id.toString() } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/discussions/:id/like', authMiddleware, async (req, res) => {
  try {
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
    const discussion = await Discussion.findById(req.params.id);
    if (!discussion) return res.status(404).json({ success: false, message: 'النقاش غير موجود' });

    const { content } = req.body;
    if (!content?.trim()) return res.status(400).json({ success: false, message: 'محتوى التعليق مطلوب' });

    const user = await User.findById(req.user.userId);
    const newComment = await Comment.create({
      discussionId: req.params.id,
      content: content.trim(),
      author: { _id: user._id, name: user.name, avatar: user.avatar, reputation: user.reputation }
    });

    await Discussion.findByIdAndUpdate(req.params.id, { $inc: { commentCount: 1 } });

    res.status(201).json({ success: true, comment: { ...newComment.toObject(), _id: newComment._id.toString() } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

// ===== CIRCLES =====
app.get('/api/circles', async (req, res) => {
  try {
    const circles = await Circle.find().lean();
    res.json({ success: true, circles: circles.map(c => ({ ...c, _id: c._id.toString() })) });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/circles/:id', async (req, res) => {
  try {
    const circle = await Circle.findById(req.params.id).lean();
    if (!circle) return res.status(404).json({ success: false, message: 'الدائرة غير موجودة' });
    res.json({ success: true, circle: { ...circle, _id: circle._id.toString() } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/circles/:id/join', authMiddleware, async (req, res) => {
  try {
    const circle = await Circle.findById(req.params.id);
    if (!circle) return res.status(404).json({ success: false, message: 'الدائرة غير موجودة' });

    const userId = req.user.userId;
    const memberIndex = circle.memberIds.indexOf(userId);
    if (memberIndex === -1) {
      circle.memberIds.push(userId);
      circle.members += 1;
    } else {
      circle.memberIds.splice(memberIndex, 1);
      circle.members -= 1;
    }
    await circle.save();
    res.json({ success: true, joined: memberIndex === -1, members: circle.members });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

// ===== USERS =====
app.get('/api/users/leaderboard', async (req, res) => {
  try {
    const users = await User.find().sort({ reputation: -1 }).limit(10).select('name avatar reputation role').lean();
    res.json({ success: true, users: users.map(u => ({ ...u, id: u._id.toString() })) });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/users/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    const userDiscussions = await Discussion.countDocuments({ 'author._id': user._id });
    res.json({
      success: true,
      user: {
        id: user._id.toString(), _id: user._id.toString(),
        name: user.name, email: user.email, avatar: user.avatar, bio: user.bio,
        reputation: user.reputation, role: user.role,
        discussions: userDiscussions, createdAt: user.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.put('/api/users/profile', authMiddleware, async (req, res) => {
  try {
    const { name, bio, avatar } = req.body;
    const updates = {};
    if (name) updates.name = name.trim();
    if (bio !== undefined) updates.bio = bio.trim();
    if (avatar) updates.avatar = avatar;

    const user = await User.findByIdAndUpdate(req.user.userId, updates, { new: true });
    if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });

    res.json({
      success: true,
      user: { id: user._id.toString(), _id: user._id.toString(), name: user.name, email: user.email, avatar: user.avatar, bio: user.bio, reputation: user.reputation, role: user.role }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

// ===== ERROR HANDLERS =====
app.use((req, res) => res.status(404).json({ success: false, message: `المسار ${req.path} غير موجود` }));
app.use((err, req, res, next) => { console.error(err.stack); res.status(500).json({ success: false, message: 'خطأ داخلي في الخادم' }); });

module.exports = app;
