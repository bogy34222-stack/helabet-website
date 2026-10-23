const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const DATA = path.join(__dirname, 'data');
const UPLOADS = path.join(__dirname, 'uploads');

fs.mkdirSync(DATA, { recursive: true });
fs.mkdirSync(UPLOADS, { recursive: true });

function readData(name, fallback = []) {
  const file = path.join(DATA, name);
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeData(name, value) {
  const file = path.join(DATA, name);
  const temp = file + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(value, null, 2));
  fs.renameSync(temp, file);
}

const usersFile = 'users.json';
const depositsFile = 'deposits.json';

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
  console.error('ERROR: SESSION_SECRET is not configured.');
  process.exit(1);
}

app.use(session({
  name: 'helabet.sid',
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: false,
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS),
  filename: (req, file, cb) => {
    cb(null, crypto.randomUUID() + path.extname(file.originalname).toLowerCase());
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    cb(null, allowed.includes(file.mimetype));
  }
});

function currentUser(req) {
  if (!req.session.userId) return null;
  return readData(usersFile).find(u => u.id === req.session.userId && u.active);
}

function requireLogin(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'سجّل الدخول أولاً' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'الصلاحية غير متاحة' });
  }
  next();
}

app.get('/api/status', (req, res) => {
  const users = readData(usersFile);
  res.json({
    ok: true,
    setupRequired: !users.some(u => u.role === 'admin'),
    loggedIn: !!currentUser(req),
    user: currentUser(req)
      ? { username: currentUser(req).username, role: currentUser(req).role }
      : null
  });
});

app.post('/api/admin/setup', async (req, res) => {
  const users = readData(usersFile);
  if (users.some(u => u.role === 'admin')) {
    return res.status(403).json({ error: 'تم إنشاء حساب الإدارة بالفعل' });
  }

  const { username, password } = req.body || {};
  if (!/^[a-zA-Z0-9_]{4,30}$/.test(username || '') ||
      typeof password !== 'string' || password.length < 12) {
    return res.status(400).json({
      error: 'اسم المستخدم من 4 إلى 30 حرفاً، وكلمة المرور 12 حرفاً على الأقل'
    });
  }

  const hash = await bcrypt.hash(password, 12);
  const admin = {
    id: crypto.randomUUID(),
    username,
    password: hash,
    role: 'admin',
    active: true,
    createdAt: new Date().toISOString()
  };

  users.push(admin);
  writeData(usersFile, users);
  req.session.userId = admin.id;
  res.json({ ok: true, message: 'تم إنشاء حساب الإدارة' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = readData(usersFile).find(
    u => u.username === username && u.active
  );

  if (!user || !(await bcrypt.compare(password || '', user.password))) {
    return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
  }

  req.session.userId = user.id;
  res.json({
    ok: true,
    user: { username: user.username, role: user.role }
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('helabet.sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', requireLogin, (req, res) => {
  res.json({
    username: req.user.username,
    role: req.user.role,
    active: req.user.active
  });
});

app.get('/api/admin/agents', requireLogin, requireAdmin, (req, res) => {
  res.json(readData(usersFile)
    .filter(u => u.role === 'agent')
    .map(({ id, username, active, createdAt }) => ({
      id, username, active, createdAt
    })));
});

app.post('/api/admin/agents', requireLogin, requireAdmin, async (req, res) => {
  const { username, password } = req.body || {};
  const users = readData(usersFile);

  if (!/^[a-zA-Z0-9_]{4,30}$/.test(username || '') ||
      typeof password !== 'string' || password.length < 12) {
    return res.status(400).json({
      error: 'اسم المستخدم من 4 إلى 30 حرفاً، وكلمة المرور 12 حرفاً على الأقل'
    });
  }

  if (users.some(u => u.username === username)) {
    return res.status(409).json({ error: 'اسم المستخدم مستخدم بالفعل' });
  }

  const agent = {
    id: crypto.randomUUID(),
    username,
    password: await bcrypt.hash(password, 12),
    role: 'agent',
    active: true,
    createdAt: new Date().toISOString()
  };

  users.push(agent);
  writeData(usersFile, users);
  res.status(201).json({
    ok: true,
    agent: { id: agent.id, username: agent.username, active: true }
  });
});

app.patch('/api/admin/agents/:id/toggle', requireLogin, requireAdmin, (req, res) => {
  const users = readData(usersFile);
  const agent = users.find(u => u.id === req.params.id && u.role === 'agent');
  if (!agent) return res.status(404).json({ error: 'الوكيل غير موجود' });

  agent.active = !agent.active;
  writeData(usersFile, users);
  res.json({ ok: true, active: agent.active });
});

app.post('/api/deposits', requireLogin, upload.single('proof'), (req, res) => {
  const { agencyId, txid, amount } = req.body || {};

  if (!agencyId || !txid || !req.file) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).json({
      error: 'أدخل رقم الوكالة ورقم العملية وأرفق صورة إثبات التحويل'
    });
  }

  const deposits = readData(depositsFile);
  const deposit = {
    id: crypto.randomUUID(),
    username: req.user.username,
    agencyId: String(agencyId).slice(0, 80),
    txid: String(txid).slice(0, 200),
    amount: String(amount || '').slice(0, 30),
    proof: req.file.filename,
    status: 'pending',
    createdAt: new Date().toISOString()
  };

  deposits.push(deposit);
  writeData(depositsFile, deposits);
  res.status(201).json({
    ok: true,
    message: 'تم استلام طلب الإيداع، برجاء انتظار المراجعة النهائية',
    id: deposit.id
  });
});

app.get('/api/deposits', requireLogin, (req, res) => {
  const deposits = readData(depositsFile)
    .filter(d => d.username === req.user.username)
    .map(({ proof, ...d }) => d);
  res.json(deposits);
});

app.get('/api/admin/deposits', requireLogin, requireAdmin, (req, res) => {
  res.json(readData(depositsFile).map(({ proof, ...d }) => d));
});

app.patch('/api/admin/deposits/:id/status', requireLogin, requireAdmin, (req, res) => {
  const { status } = req.body || {};
  if (!['approved', 'rejected', 'pending'].includes(status)) {
    return res.status(400).json({ error: 'حالة الطلب غير صحيحة' });
  }

  const deposits = readData(depositsFile);
  const deposit = deposits.find(d => d.id === req.params.id);
  if (!deposit) return res.status(404).json({ error: 'الطلب غير موجود' });

  deposit.status = status;
  deposit.reviewedAt = new Date().toISOString();
  writeData(depositsFile, deposits);
  res.json({ ok: true, status });
});

app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => {
  console.error(err.message);
  res.status(400).json({ error: 'تعذر إتمام الطلب. راجع البيانات وحاول مرة أخرى.' });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`HelaBet local server: http://127.0.0.1:${PORT}`);
});
