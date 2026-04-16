/**
 * AporiaLab Backend API v2.0
 * منصة AporiaLab للنقاشات العربية
 */

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

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

const JWT_SECRET = process.env.JWT_SECRET || 'aporialab-secret-key-2026';

// ===== IN-MEMORY DATABASE =====
let users = [
  { id: '1', name: 'أحمد الفيصل', email: 'ahmed@aporialab.space', password: 'password123', avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=ahmed', bio: 'مهتم بالفلسفة والنقاش العقلاني', reputation: 150, role: 'user', createdAt: new Date('2026-01-01').toISOString() },
  { id: '2', name: 'سارة محمد', email: 'sara@aporialab.space', password: 'password123', avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=sara', bio: 'باحثة اجتماعية ومهتمة بحقوق الإنسان', reputation: 200, role: 'user', createdAt: new Date('2026-01-02').toISOString() },
  { id: '3', name: 'خالد العمري', email: 'khaled@aporialab.space', password: 'password123', avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=khaled', bio: 'مهتم بالسياسة والشأن العام', reputation: 180, role: 'user', createdAt: new Date('2026-01-03').toISOString() },
  { id: '4', name: 'نورة السعيد', email: 'noura@aporialab.space', password: 'password123', avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=noura', bio: 'أستاذة فلسفة في الجامعة', reputation: 300, role: 'moderator', createdAt: new Date('2026-01-04').toISOString() },
  { id: '5', name: 'فهد الراشد', email: 'fahd@aporialab.space', password: 'password123', avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=fahd', bio: 'محلل سياسي وكاتب رأي', reputation: 120, role: 'user', createdAt: new Date('2026-01-05').toISOString() }
];

let discussions = [
  { _id: 'd1', title: 'هل الديمقراطية النظام الأمثل للحكم في العالم العربي؟', content: 'نقاش مفتوح حول إمكانية تطبيق الديمقراطية في السياق العربي مع مراعاة الخصوصية الثقافية والدينية والتاريخية', category: 'advanced', tags: ['سياسة', 'ديمقراطية', 'حوكمة'], author: { _id: '4', name: 'نورة السعيد', avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=noura', reputation: 300 }, views: 1240, upvotes: ['1', '2', '3'], commentCount: 47, createdAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString() },
  { _id: 'd2', title: 'الذكاء الاصطناعي والأخلاق: أين نضع الحدود؟', content: 'مع تسارع تطور الذكاء الاصطناعي، كيف نضمن أنه يخدم الإنسانية دون أن يهدد قيمنا وحقوقنا الأساسية؟', category: 'intermediate', tags: ['تكنولوجيا', 'أخلاق', 'ذكاء اصطناعي'], author: { _id: '2', name: 'سارة محمد', avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=sara', reputation: 200 }, views: 892, upvotes: ['1', '4'], commentCount: 33, createdAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString() },
  { _id: 'd3', title: 'هل التعليم التقليدي كافٍ في عصر المعلومات؟', content: 'مناقشة جدية حول مدى ملاءمة مناهج التعليم الحالية لمتطلبات سوق العمل والحياة في القرن الحادي والعشرين', category: 'beginner', tags: ['تعليم', 'مستقبل', 'شباب'], author: { _id: '1', name: 'أحمد الفيصل', avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=ahmed', reputation: 150 }, views: 654, upvotes: ['2', '3', '5'], commentCount: 28, createdAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString() },
  { _id: 'd4', title: 'الهوية الثقافية في زمن العولمة', content: 'كيف نحافظ على هويتنا وموروثنا الثقافي في ظل موجة العولمة المتسارعة وانفتاح العالم؟', category: 'advanced', tags: ['ثقافة', 'هوية', 'عولمة'], author: { _id: '3', name: 'خالد العمري', avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=khaled', reputation: 180 }, views: 445, upvotes: ['1'], commentCount: 19, createdAt: new Date(Date.now() - 4 * 24 * 60 * 60 * 1000).toISOString() },
  { _id: 'd5', title: 'أزمة المناخ: مسؤولية الأفراد أم الحكومات؟', content: 'نقاش حول توزيع المسؤولية في مواجهة التغير المناخي بين المواطن العادي والجهات الحكومية والشركات الكبرى', category: 'intermediate', tags: ['بيئة', 'مناخ', 'سياسة'], author: { _id: '5', name: 'فهد الراشد', avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=fahd', reputation: 120 }, views: 387, upvotes: ['2', '4'], commentCount: 15, createdAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString() },
  { _id: 'd6', title: 'حرية التعبير: متى تصبح خطراً على المجتمع؟', content: 'هل لحرية التعبير حدود يجب احترامها؟ وأين يقع الخط الفاصل بين الرأي الحر والخطاب الضار؟', category: 'advanced', tags: ['حرية', 'قانون', 'مجتمع'], author: { _id: '4', name: 'نورة السعيد', avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=noura', reputation: 300 }, views: 312, upvotes: ['1', '3', '5'], commentCount: 41, createdAt: new Date(Date.now() - 6 * 24 * 60 * 60 * 1000).toISOString() }
];

let comments = [];

let circles = [
  { _id: 'ci1', name: 'دائرة الفلسفة والأخلاق', description: 'نقاشات عميقة في الفلسفة الأخلاقية وقضايا الوجود والمعرفة', category: 'فلسفة', members: 1240, isPrivate: false, icon: 'Brain', color: 'from-purple-500/20 to-blue-500/20', memberIds: ['1', '4'], createdAt: new Date('2026-01-01').toISOString() },
  { _id: 'ci2', name: 'دائرة الشؤون السياسية', description: 'تحليل الأحداث السياسية والسياسات العامة بموضوعية وعمق', category: 'سياسة', members: 876, isPrivate: false, icon: 'Scale', color: 'from-blue-500/20 to-cyan-500/20', memberIds: ['3', '5'], createdAt: new Date('2026-01-02').toISOString() },
  { _id: 'ci3', name: 'دائرة التكنولوجيا والمجتمع', description: 'فهم التأثيرات الاجتماعية للتكنولوجيا الحديثة والذكاء الاصطناعي', category: 'تكنولوجيا', members: 654, isPrivate: false, icon: 'Cpu', color: 'from-green-500/20 to-emerald-500/20', memberIds: ['2'], createdAt: new Date('2026-01-03').toISOString() },
  { _id: 'ci4', name: 'دائرة الاقتصاد والتنمية', description: 'نقاشات حول التحديات الاقتصادية وسبل التنمية المستدامة', category: 'اقتصاد', members: 432, isPrivate: false, icon: 'TrendingUp', color: 'from-orange-500/20 to-yellow-500/20', memberIds: [], createdAt: new Date('2026-01-04').toISOString() }
];

// ===== AUTH MIDDLEWARE =====
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
  res.json({ name: 'AporiaLab API', version: '2.0.0', status: 'running', timestamp: new Date().toISOString() });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString(), users: users.length, discussions: discussions.length });
});

// ===== AUTH =====
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'البريد الإلكتروني وكلمة المرور مطلوبان' });
    const user = users.find(u => u.email === email.toLowerCase().trim());
    if (!user || user.password !== password) return res.status(401).json({ success: false, message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: { id: user.id, _id: user.id, name: user.name, email: user.email, avatar: user.avatar, bio: user.bio, reputation: user.reputation, role: user.role } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.post('/api/auth/register', (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ success: false, message: 'جميع الحقول مطلوبة' });
    if (password.length < 6) return res.status(400).json({ success: false, message: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
    if (users.find(u => u.email === email.toLowerCase().trim())) return res.status(400).json({ success: false, message: 'هذا البريد الإلكتروني مسجل مسبقاً' });
    const newUser = { id: String(Date.now()), name: name.trim(), email: email.toLowerCase().trim(), password, avatar: `https://api.dicebear.com/7.x/avataaars/svg?seed=${encodeURIComponent(email)}`, bio: '', reputation: 0, role: 'user', createdAt: new Date().toISOString() };
    users.push(newUser);
    const token = jwt.sign({ userId: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({ success: true, token, user: { id: newUser.id, _id: newUser.id, name: newUser.name, email: newUser.email, avatar: newUser.avatar, bio: newUser.bio, reputation: newUser.reputation, role: newUser.role } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'خطأ في الخادم' });
  }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
  res.json({ success: true, user: { id: user.id, _id: user.id, name: user.name, email: user.email, avatar: user.avatar, bio: user.bio, reputation: user.reputation, role: user.role } });
});

// ===== DISCUSSIONS =====
app.get('/api/discussions', (req, res) => {
  const { sort = 'trending', filter, level, page = 1, limit = 10 } = req.query;
  let result = [...discussions];
  if (level && level !== 'all') result = result.filter(d => d.category === level);
  if (filter && filter !== 'all') result = result.filter(d => d.category === filter);
  if (sort === 'trending') result.sort((a, b) => (b.views + b.upvotes.length * 10) - (a.views + a.upvotes.length * 10));
  else if (sort === 'featured') result.sort((a, b) => b.upvotes.length - a.upvotes.length);
  else if (sort === 'live') result.sort((a, b) => b.commentCount - a.commentCount);
  else if (sort === 'timed') result.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const pageNum = parseInt(page), limitNum = parseInt(limit), total = result.length;
  res.json({ success: true, discussions: result.slice((pageNum - 1) * limitNum, pageNum * limitNum), pagination: { page: pageNum, pages: Math.ceil(total / limitNum), total } });
});

app.get('/api/discussions/:id', (req, res) => {
  const discussion = discussions.find(d => d._id === req.params.id);
  if (!discussion) return res.status(404).json({ success: false, message: 'النقاش غير موجود' });
  discussion.views += 1;
  res.json({ success: true, discussion: { ...discussion, comments: comments.filter(c => c.discussionId === req.params.id) } });
});

app.post('/api/discussions', authMiddleware, (req, res) => {
  const { title, description, content, level, tags } = req.body;
  if (!title || !content) return res.status(400).json({ success: false, message: 'العنوان والمحتوى مطلوبان' });
  const user = users.find(u => u.id === req.user.userId);
  const newDiscussion = { _id: `d${Date.now()}`, title: title.trim(), content: (content || description || '').trim(), category: level || 'beginner', tags: tags || [], author: { _id: user.id, name: user.name, avatar: user.avatar, reputation: user.reputation }, views: 0, upvotes: [], commentCount: 0, createdAt: new Date().toISOString() };
  discussions.unshift(newDiscussion);
  const userIndex = users.findIndex(u => u.id === req.user.userId);
  if (userIndex !== -1) users[userIndex].reputation += 10;
  res.status(201).json({ success: true, discussion: newDiscussion });
});

app.post('/api/discussions/:id/like', authMiddleware, (req, res) => {
  const discussion = discussions.find(d => d._id === req.params.id);
  if (!discussion) return res.status(404).json({ success: false, message: 'النقاش غير موجود' });
  const userId = req.user.userId, likeIndex = discussion.upvotes.indexOf(userId);
  if (likeIndex === -1) discussion.upvotes.push(userId);
  else discussion.upvotes.splice(likeIndex, 1);
  res.json({ success: true, liked: likeIndex === -1, upvotesCount: discussion.upvotes.length });
});

app.post('/api/discussions/:id/comments', authMiddleware, (req, res) => {
  const discussion = discussions.find(d => d._id === req.params.id);
  if (!discussion) return res.status(404).json({ success: false, message: 'النقاش غير موجود' });
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ success: false, message: 'محتوى التعليق مطلوب' });
  const user = users.find(u => u.id === req.user.userId);
  const newComment = { _id: `c${Date.now()}`, discussionId: req.params.id, content: content.trim(), author: { _id: user.id, name: user.name, avatar: user.avatar, reputation: user.reputation }, upvotes: [], createdAt: new Date().toISOString() };
  comments.push(newComment);
  discussion.commentCount += 1;
  res.status(201).json({ success: true, comment: newComment });
});

// ===== CIRCLES =====
app.get('/api/circles', (req, res) => res.json({ success: true, circles }));

app.get('/api/circles/:id', (req, res) => {
  const circle = circles.find(c => c._id === req.params.id);
  if (!circle) return res.status(404).json({ success: false, message: 'الدائرة غير موجودة' });
  res.json({ success: true, circle });
});

app.post('/api/circles/:id/join', authMiddleware, (req, res) => {
  const circle = circles.find(c => c._id === req.params.id);
  if (!circle) return res.status(404).json({ success: false, message: 'الدائرة غير موجودة' });
  const userId = req.user.userId, memberIndex = circle.memberIds.indexOf(userId);
  if (memberIndex === -1) { circle.memberIds.push(userId); circle.members += 1; res.json({ success: true, joined: true, members: circle.members }); }
  else { circle.memberIds.splice(memberIndex, 1); circle.members -= 1; res.json({ success: true, joined: false, members: circle.members }); }
});

// ===== USERS =====
app.get('/api/users/leaderboard', (req, res) => {
  const leaderboard = users.map(u => ({ id: u.id, name: u.name, avatar: u.avatar, reputation: u.reputation, role: u.role })).sort((a, b) => b.reputation - a.reputation).slice(0, 10);
  res.json({ success: true, users: leaderboard });
});

app.get('/api/users/profile', authMiddleware, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
  const userDiscussions = discussions.filter(d => d.author._id === user.id);
  res.json({ success: true, user: { id: user.id, _id: user.id, name: user.name, email: user.email, avatar: user.avatar, bio: user.bio, reputation: user.reputation, role: user.role, discussions: userDiscussions.length, createdAt: user.createdAt } });
});

app.put('/api/users/profile', authMiddleware, (req, res) => {
  const userIndex = users.findIndex(u => u.id === req.user.userId);
  if (userIndex === -1) return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
  const { name, bio, avatar } = req.body;
  if (name) users[userIndex].name = name.trim();
  if (bio !== undefined) users[userIndex].bio = bio.trim();
  if (avatar) users[userIndex].avatar = avatar;
  const user = users[userIndex];
  res.json({ success: true, user: { id: user.id, _id: user.id, name: user.name, email: user.email, avatar: user.avatar, bio: user.bio, reputation: user.reputation, role: user.role } });
});

// ===== ERROR HANDLERS =====
app.use((req, res) => res.status(404).json({ success: false, message: `المسار ${req.path} غير موجود` }));
app.use((err, req, res, next) => { console.error(err.stack); res.status(500).json({ success: false, message: 'خطأ داخلي في الخادم' }); });

module.exports = app;
