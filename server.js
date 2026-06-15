require('dotenv').config();
const express      = require('express');
const cors         = require('cors');
const rateLimit    = require('express-rate-limit');
const helmet       = require('helmet');
const compression  = require('compression');
const { createClient } = require('@supabase/supabase-js');
const path         = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// ════════════════════════════════════════════════════════════════
// ✅ FIX CRÍTICO: trust proxy
// Causa del error ERR_ERL_UNEXPECTED_X_FORWARDED_FOR:
//   Render (y la mayoría de PaaS) pasan la IP real del cliente
//   en el header X-Forwarded-For. express-rate-limit detecta
//   ese header y lanza un ValidationError porque Express no
//   estaba configurado para confiar en el proxy.
// Solución: app.set('trust proxy', 1) le dice a Express que
//   confíe en el primer hop del proxy (el load balancer de Render).
//   Esto hace que req.ip sea la IP real del cliente y que
//   express-rate-limit la use correctamente sin errores.
// ════════════════════════════════════════════════════════════════
app.set('trust proxy', 1);

// ════════════════════════════════════════════════════════════════
// SUPABASE CLIENTS
// supabase  → verifica tokens JWT (anon key)
// adminDb   → operaciones privilegiadas (service role)
// ════════════════════════════════════════════════════════════════
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
  console.error('❌ Faltan variables de entorno de Supabase. Revisa tu .env');
  process.exit(1);
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

const adminDb = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

// ════════════════════════════════════════════════════════════════
// SECURITY MIDDLEWARE
// ════════════════════════════════════════════════════════════════

// Helmet: sets security headers (XSS, clickjacking, MIME sniffing, etc.)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://api.anthropic.com"],
      styleSrc:       ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://fonts.gstatic.com"],
      fontSrc:        ["'self'", "https://fonts.gstatic.com"],
      imgSrc:         ["'self'", "data:", "https:"],
      connectSrc:     ["'self'", "https://api.anthropic.com", process.env.SUPABASE_URL || ""],
      frameSrc:       ["'none'"],
      objectSrc:      ["'none'"],
      upgradeInsecureRequests: IS_PRODUCTION ? [] : null,
    }
  },
  crossOriginEmbedderPolicy: false,  // needed for fonts/external resources
}));

// Compression: gzip responses
app.use(compression());

// CORS
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ['*'];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS: origen no permitido'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// Body parsing with size limit to prevent DoS
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: IS_PRODUCTION ? '1d' : 0,
  etag: true,
}));

// ════════════════════════════════════════════════════════════════
// RATE LIMITING
// Con trust proxy activado, estos limiters usan la IP real
// ════════════════════════════════════════════════════════════════
const makeLimit = (max, windowMs = 60_000, message = 'Demasiadas solicitudes. Intenta más tarde.') =>
  rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: message },
    // skipSuccessfulRequests: false (default) — cuenta todos los intentos
    handler: (req, res, next, options) => {
      res.status(options.statusCode).json(options.message);
    },
  });

const authLimiter  = makeLimit(10, 60_000, 'Demasiados intentos de autenticación. Espera 1 minuto.');
const scoreLimiter = makeLimit(20, 60_000, 'Demasiados scores enviados. Espera un momento.');
const apiLimiter   = makeLimit(200, 60_000);
const adminLimiter = makeLimit(30, 60_000, 'Demasiadas solicitudes administrativas.');

app.use('/register', authLimiter);
app.use('/login',    authLimiter);
app.use('/score',    scoreLimiter);
app.use('/admin',    adminLimiter);
app.use(apiLimiter);

// ════════════════════════════════════════════════════════════════
// CACHE IN-MEMORY SIMPLE (para subjects que cambian poco)
// En producción escalar a Redis
// ════════════════════════════════════════════════════════════════
const cache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutos

function getCache(key) {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) { cache.delete(key); return null; }
  return entry.value;
}

function setCache(key, value, ttl = CACHE_TTL) {
  cache.set(key, { value, expiresAt: Date.now() + ttl });
}

// ════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════
function getEducationLevel(age) {
  const n = parseInt(age, 10);
  if (n >= 6  && n <= 11)  return 'primaria';
  if (n >= 12 && n <= 14)  return 'secundaria';
  if (n >= 15 && n <= 17)  return 'preparatoria';
  if (n >= 18 && n <= 100) return 'universidad';
  return null;
}

// Sanitiza strings: elimina caracteres de control y limita longitud
function sanitizeString(str, maxLen = 255) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>"'`]/g, '').trim().slice(0, maxLen);
}

// Valida email básico
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Wrapper para capturar errores de rutas async
const asyncHandler = fn => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// ════════════════════════════════════════════════════════════════
// AUTH MIDDLEWARE
// ════════════════════════════════════════════════════════════════
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token de autenticación requerido' });
  }

  const token = authHeader.split(' ')[1];
  if (!token || token.length < 10) {
    return res.status(401).json({ error: 'Token malformado' });
  }

  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Token inválido o expirado' });

    const { data: profile, error: pErr } = await adminDb
      .from('profiles')
      .select('id, username, role, age, education_level, avatar_color, is_active')
      .eq('id', user.id)
      .maybeSingle();

    if (pErr || !profile) return res.status(401).json({ error: 'Perfil no encontrado' });
    if (!profile.is_active) return res.status(403).json({ error: 'Cuenta desactivada. Contacta al administrador.' });

    req.user    = user;
    req.profile = profile;
    next();
  } catch (err) {
    console.error('Error en requireAuth:', err.message);
    return res.status(500).json({ error: 'Error interno de autenticación' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.profile || !roles.includes(req.profile.role)) {
      return res.status(403).json({
        error: 'Acceso denegado',
        required: roles,
        current: req.profile?.role || 'none'
      });
    }
    next();
  };
}

// ════════════════════════════════════════════════════════════════
// RUTAS PÚBLICAS
// ════════════════════════════════════════════════════════════════

app.get('/health', (_, res) => {
  res.json({
    status: 'ok',
    ts: Date.now(),
    env: IS_PRODUCTION ? 'production' : 'development',
    version: process.env.npm_package_version || '1.0.0',
  });
});

// GET /subjects – materias activas (con caché)
app.get('/subjects', asyncHandler(async (_, res) => {
  const cached = getCache('subjects');
  if (cached) return res.json({ subjects: cached, cached: true });

  const { data, error } = await adminDb
    .from('subjects')
    .select('id, name, slug, description, icon')
    .eq('is_active', true)
    .order('sort_order');

  if (error) return res.status(500).json({ error: 'Error cargando materias' });

  setCache('subjects', data);
  res.json({ subjects: data });
}));

// GET /leaderboard?subject_slug=&education_level=&limit=
app.get('/leaderboard', asyncHandler(async (req, res) => {
  const { subject_slug, education_level } = req.query;
  const safeLimit = Math.min(parseInt(req.query.limit) || 20, 100);

  let subjectId = null;
  if (subject_slug) {
    const cacheKey = `subject_id_${subject_slug}`;
    subjectId = getCache(cacheKey);
    if (!subjectId) {
      const { data: sub } = await adminDb
        .from('subjects').select('id').eq('slug', subject_slug).maybeSingle();
      subjectId = sub?.id || null;
      if (subjectId) setCache(cacheKey, subjectId, 10 * 60 * 1000);
    }
    if (!subjectId) return res.json({ leaderboard: [] });
  }

  // Fetch more to allow client-side education_level filter
  const fetchLimit = education_level ? safeLimit * 5 : safeLimit;

  let query = adminDb
    .from('scores')
    .select('best_score, total_xp, current_level, games_played, user_id, subject_id, subjects(name, slug, icon), profiles(username, education_level, avatar_color)')
    .order('best_score', { ascending: false })
    .limit(fetchLimit);

  if (subjectId) query = query.eq('subject_id', subjectId);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: 'Error cargando leaderboard' });

  let rows = data || [];
  if (education_level) rows = rows.filter(r => r.profiles?.education_level === education_level);
  rows = rows.slice(0, safeLimit);

  res.json({
    leaderboard: rows.map((r, i) => ({
      rank:            i + 1,
      username:        r.profiles?.username || '???',
      education_level: r.profiles?.education_level,
      avatar_color:    r.profiles?.avatar_color || '#6366f1',
      subject:         r.subjects?.name,
      subject_slug:    r.subjects?.slug,
      subject_icon:    r.subjects?.icon || '📚',
      best_score:      r.best_score,
      total_xp:        r.total_xp,
      games_played:    r.games_played,
      level:           r.current_level,
    }))
  });
}));

// ════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════════════════════════════

// POST /register
app.post('/register', asyncHandler(async (req, res) => {
  const email    = sanitizeString(req.body.email || '', 254).toLowerCase();
  const password = req.body.password || '';
  const username = sanitizeString(req.body.username || '', 20);
  const age      = req.body.age;

  // Validaciones
  if (!email || !password || !username || age == null)
    return res.status(400).json({ error: 'Todos los campos son obligatorios (email, password, username, age)' });

  if (!isValidEmail(email))
    return res.status(400).json({ error: 'Formato de email inválido' });

  if (password.length < 8)
    return res.status(400).json({ error: 'Contraseña mínimo 8 caracteres' });

  if (password.length > 128)
    return res.status(400).json({ error: 'Contraseña demasiado larga' });

  // Evitar contraseñas triviales
  if (/^(.)\1+$/.test(password) || ['12345678','password','contraseña','87654321'].includes(password.toLowerCase()))
    return res.status(400).json({ error: 'Contraseña demasiado sencilla. Elige una más segura.' });

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
    return res.status(400).json({ error: 'Username: 3–20 caracteres (letras, números o _). Sin espacios.' });

  const parsedAge = parseInt(age, 10);
  if (isNaN(parsedAge))
    return res.status(400).json({ error: 'La edad debe ser un número' });

  const education_level = getEducationLevel(parsedAge);
  if (!education_level)
    return res.status(400).json({ error: 'Edad inválida. Rango permitido: 6–100 años' });

  // Unicidad del username (case-insensitive check)
  const { data: taken } = await adminDb
    .from('profiles')
    .select('id')
    .ilike('username', username)
    .maybeSingle();

  if (taken) return res.status(409).json({ error: 'El username ya está en uso. Elige otro.' });

  // Crear usuario en Supabase Auth
  const { data: auth, error: authErr } = await adminDb.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
  });

  if (authErr) {
    const msg = authErr.message?.toLowerCase().includes('already')
      ? 'El email ya está registrado'
      : 'Error creando la cuenta. Intenta de nuevo.';
    return res.status(400).json({ error: msg });
  }

  // Crear perfil
  const { error: profileErr } = await adminDb.from('profiles').insert({
    id: auth.user.id,
    username,
    role: 'student',
    age: parsedAge,
    education_level,
    avatar_color: `hsl(${Math.floor(Math.random() * 360)}, 70%, 55%)`,
  });

  if (profileErr) {
    // Rollback: eliminar el usuario de Auth si el perfil falló
    await adminDb.auth.admin.deleteUser(auth.user.id);
    console.error('Error creando perfil:', profileErr.message);
    return res.status(500).json({ error: 'Error creando perfil. Intenta de nuevo.' });
  }

  res.status(201).json({
    message: '¡Cuenta creada exitosamente!',
    username,
    education_level,
  });
}));

// POST /login
app.post('/login', asyncHandler(async (req, res) => {
  const email    = sanitizeString(req.body.email || '', 254).toLowerCase();
  const password = req.body.password || '';

  if (!email || !password)
    return res.status(400).json({ error: 'Email y contraseña requeridos' });

  if (!isValidEmail(email))
    return res.status(400).json({ error: 'Formato de email inválido' });

  const { data, error } = await supabase.auth.signInWithPassword({ email, password });

  // Mensaje genérico para no revelar si el email existe
  if (error) return res.status(401).json({ error: 'Credenciales inválidas' });

  const { data: profile } = await adminDb
    .from('profiles')
    .select('username, role, age, education_level, avatar_color, is_active')
    .eq('id', data.user.id)
    .single();

  if (!profile?.is_active) {
    return res.status(403).json({ error: 'Cuenta desactivada. Contacta al administrador.' });
  }

  // Retornar también el refresh_token para renovación silenciosa en cliente
  res.json({
    token:         data.session.access_token,
    refresh_token: data.session.refresh_token,
    expires_at:    data.session.expires_at,
    user: {
      id:    data.user.id,
      email: data.user.email,
      ...profile,
    },
  });
}));

// POST /refresh  { refresh_token }
app.post('/refresh', asyncHandler(async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ error: 'refresh_token requerido' });

  const { data, error } = await supabase.auth.refreshSession({ refresh_token });
  if (error || !data.session) return res.status(401).json({ error: 'Sesión expirada. Inicia sesión nuevamente.' });

  res.json({
    token:         data.session.access_token,
    refresh_token: data.session.refresh_token,
    expires_at:    data.session.expires_at,
  });
}));

// ════════════════════════════════════════════════════════════════
// RUTAS AUTENTICADAS – ESTUDIANTE
// ════════════════════════════════════════════════════════════════

// GET /me
app.get('/me', requireAuth, asyncHandler(async (req, res) => {
  const { data: scoreData } = await adminDb
    .from('scores')
    .select('best_score, total_xp, current_level, games_played, last_played_at, subjects(name, slug, icon)')
    .eq('user_id', req.profile.id)
    .order('total_xp', { ascending: false });

  res.json({
    id:              req.user.id,
    email:           req.user.email,
    username:        req.profile.username,
    role:            req.profile.role,
    age:             req.profile.age,
    education_level: req.profile.education_level,
    avatar_color:    req.profile.avatar_color,
    scores:          scoreData || [],
  });
}));

// POST /score  { subject_slug, score }
app.post('/score', requireAuth, asyncHandler(async (req, res) => {
  const { subject_slug, score, questions_total, correct_answers } = req.body;

  if (!subject_slug || score == null)
    return res.status(400).json({ error: 'subject_slug y score son obligatorios' });

  const parsed = parseInt(score, 10);
  if (isNaN(parsed) || parsed < 0 || parsed > 10_000)
    return res.status(400).json({ error: 'Score inválido (rango: 0–10000)' });

  // Validar que subject_slug no contenga inyecciones
  if (!/^[a-z0-9_-]{1,50}$/.test(subject_slug))
    return res.status(400).json({ error: 'subject_slug inválido' });

  // Verificar materia
  const { data: subject } = await adminDb
    .from('subjects')
    .select('id, name')
    .eq('slug', subject_slug)
    .eq('is_active', true)
    .maybeSingle();

  if (!subject) return res.status(404).json({ error: 'Materia no encontrada o inactiva' });

  // Score actual
  const { data: current } = await adminDb
    .from('scores')
    .select('id, best_score, total_xp, games_played')
    .eq('user_id', req.profile.id)
    .eq('subject_id', subject.id)
    .maybeSingle();

  // XP: proporcional al score, bonus si fue récord
  const earnedXP   = Math.max(1, Math.floor(parsed / 10));
  const newBest    = current ? Math.max(current.best_score, parsed) : parsed;
  const newXP      = (current?.total_xp     || 0) + earnedXP;
  const newGames   = (current?.games_played || 0) + 1;
  const newLevel   = Math.floor(newXP / 100) + 1;
  const isNewBest  = !current || parsed > current.best_score;

  const scorePayload = {
    best_score:     newBest,
    total_xp:       newXP,
    current_level:  newLevel,
    games_played:   newGames,
    last_played_at: new Date().toISOString(),
  };

  if (current) {
    await adminDb.from('scores').update(scorePayload).eq('id', current.id);
  } else {
    await adminDb.from('scores').insert({
      user_id:    req.profile.id,
      subject_id: subject.id,
      best_score: parsed,
      total_xp:   earnedXP,
      current_level: 1,
      games_played: 1,
    });
  }

  // Calcular insignias nuevas (lógica extensible)
  const badges = [];
  if (isNewBest && parsed >= 900)  badges.push({ id: 'perfect',   label: '¡Perfecto!',    icon: '⭐' });
  if (isNewBest && parsed >= 700)  badges.push({ id: 'great',     label: '¡Excelente!',   icon: '🏆' });
  if (newGames === 1)              badges.push({ id: 'first_game',label: 'Primera partida',icon: '🎮' });
  if (newGames === 10)             badges.push({ id: 'ten_games', label: '10 partidas',    icon: '🔥' });
  if (newLevel > (current ? Math.floor((current.total_xp || 0) / 100) + 1 : 1))
    badges.push({ id: 'level_up', label: `¡Nivel ${newLevel}!`, icon: '⬆️' });

  res.json({
    message:     isNewBest ? '¡Nuevo récord personal!' : '¡Score guardado!',
    best_score:  newBest,
    total_xp:    newXP,
    level:       newLevel,
    earned_xp:   earnedXP,
    is_new_best: isNewBest,
    games_played: newGames,
    badges,
  });
}));

// ════════════════════════════════════════════════════════════════
// RUTAS AUTENTICADAS – PROFESOR
// ════════════════════════════════════════════════════════════════

// GET /teacher/students?subject_slug=&education_level=
app.get('/teacher/students', requireAuth, requireRole('teacher', 'admin', 'school_admin'), asyncHandler(async (req, res) => {
  const { subject_slug, education_level } = req.query;

  const { data: relations, error: relErr } = await adminDb
    .from('teacher_students')
    .select('student_id')
    .eq('teacher_id', req.profile.id);

  if (relErr)           return res.status(500).json({ error: 'Error obteniendo relaciones' });
  if (!relations?.length) return res.json({ students: [], total: 0 });

  const studentIds = relations.map(r => r.student_id);

  let profileQ = adminDb
    .from('profiles')
    .select('id, username, age, education_level, avatar_color, created_at')
    .in('id', studentIds)
    .eq('is_active', true);

  if (education_level) profileQ = profileQ.eq('education_level', education_level);

  const { data: students, error: studErr } = await profileQ;
  if (studErr) return res.status(500).json({ error: 'Error obteniendo estudiantes' });

  let subjectId = null;
  if (subject_slug) {
    const { data: sub } = await adminDb
      .from('subjects').select('id').eq('slug', subject_slug).maybeSingle();
    subjectId = sub?.id || null;
  }

  let scoreQ = adminDb
    .from('scores')
    .select('user_id, best_score, total_xp, current_level, games_played, last_played_at, subjects(name, slug, icon)')
    .in('user_id', studentIds);

  if (subjectId) scoreQ = scoreQ.eq('subject_id', subjectId);

  const { data: allScores } = await scoreQ;

  const result = (students || []).map(s => {
    const scores = (allScores || []).filter(sc => sc.user_id === s.id);
    return {
      ...s,
      scores: scores.map(sc => ({
        subject:      sc.subjects?.name,
        icon:         sc.subjects?.icon,
        slug:         sc.subjects?.slug,
        best_score:   sc.best_score,
        total_xp:     sc.total_xp,
        level:        sc.current_level,
        games_played: sc.games_played,
        last_played:  sc.last_played_at,
      })),
      total_xp:     scores.reduce((s, sc) => s + sc.total_xp, 0),
      best_overall: scores.reduce((m, sc) => Math.max(m, sc.best_score), 0),
      total_games:  scores.reduce((s, sc) => s + sc.games_played, 0),
    };
  });

  result.sort((a, b) => b.total_xp - a.total_xp);
  res.json({ students: result, total: result.length });
}));

// GET /teacher/leaderboard?subject_slug=
app.get('/teacher/leaderboard', requireAuth, requireRole('teacher', 'admin', 'school_admin'), asyncHandler(async (req, res) => {
  const { subject_slug } = req.query;

  const { data: relations } = await adminDb
    .from('teacher_students')
    .select('student_id')
    .eq('teacher_id', req.profile.id);

  if (!relations?.length) return res.json({ leaderboard: [] });
  const studentIds = relations.map(r => r.student_id);

  let subjectId = null;
  if (subject_slug) {
    const { data: sub } = await adminDb
      .from('subjects').select('id').eq('slug', subject_slug).maybeSingle();
    subjectId = sub?.id || null;
  }

  let query = adminDb
    .from('scores')
    .select('best_score, total_xp, current_level, games_played, user_id, subjects(name, slug, icon), profiles(username, education_level, avatar_color)')
    .in('user_id', studentIds)
    .order('best_score', { ascending: false })
    .limit(100);

  if (subjectId) query = query.eq('subject_id', subjectId);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: 'Error cargando ranking' });

  res.json({
    leaderboard: (data || []).map((r, i) => ({
      rank:            i + 1,
      username:        r.profiles?.username || '???',
      education_level: r.profiles?.education_level,
      avatar_color:    r.profiles?.avatar_color || '#6366f1',
      subject:         r.subjects?.name,
      subject_icon:    r.subjects?.icon || '📚',
      best_score:      r.best_score,
      total_xp:        r.total_xp,
      games_played:    r.games_played,
      level:           r.current_level,
    }))
  });
}));

// POST /teacher/assign-student  { student_id }
app.post('/teacher/assign-student', requireAuth, requireRole('teacher', 'admin', 'school_admin'), asyncHandler(async (req, res) => {
  const { student_id } = req.body;
  if (!student_id) return res.status(400).json({ error: 'student_id es requerido' });

  // Verificar que el student_id sea un UUID válido
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(student_id))
    return res.status(400).json({ error: 'student_id inválido' });

  // Verificar que el estudiante exista y sea 'student'
  const { data: student } = await adminDb
    .from('profiles')
    .select('id, username, role')
    .eq('id', student_id)
    .maybeSingle();

  if (!student) return res.status(404).json({ error: 'Estudiante no encontrado' });
  if (student.role !== 'student') return res.status(400).json({ error: 'El usuario no es un estudiante' });
  if (student_id === req.profile.id) return res.status(400).json({ error: 'No puedes asignarte a ti mismo' });

  const { error } = await adminDb
    .from('teacher_students')
    .insert({ teacher_id: req.profile.id, student_id });

  if (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'El estudiante ya está asignado a este profesor' });
    return res.status(400).json({ error: error.message });
  }

  res.json({ message: `Estudiante "${student.username}" asignado correctamente` });
}));

// DELETE /teacher/remove-student/:student_id
app.delete('/teacher/remove-student/:student_id', requireAuth, requireRole('teacher', 'admin', 'school_admin'), asyncHandler(async (req, res) => {
  const { student_id } = req.params;

  const { error } = await adminDb
    .from('teacher_students')
    .delete()
    .eq('teacher_id', req.profile.id)
    .eq('student_id', student_id);

  if (error) return res.status(400).json({ error: error.message });
  res.json({ message: 'Estudiante removido del grupo' });
}));

// ════════════════════════════════════════════════════════════════
// RUTAS ADMIN
// ════════════════════════════════════════════════════════════════

// GET /admin/users?role=&limit=&offset=
app.get('/admin/users', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const { role, education_level } = req.query;
  const limit  = Math.min(parseInt(req.query.limit)  || 50, 200);
  const offset = Math.max(parseInt(req.query.offset) || 0, 0);

  let query = adminDb
    .from('profiles')
    .select('id, username, role, age, education_level, avatar_color, is_active, created_at', { count: 'exact' })
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  if (role)            query = query.eq('role', role);
  if (education_level) query = query.eq('education_level', education_level);

  const { data, error, count } = await query;
  if (error) return res.status(500).json({ error: error.message });

  res.json({ users: data, total: count, limit, offset });
}));

// POST /admin/promote  { user_id, role }
// Protegida por: JWT admin + override_key como capa extra
app.post('/admin/promote', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const { user_id, role, override_key } = req.body;

  if (!override_key || override_key !== process.env.ADMIN_OVERRIDE_KEY)
    return res.status(403).json({ error: 'Clave de override inválida' });

  const validRoles = ['student', 'teacher', 'admin', 'school_admin'];
  if (!validRoles.includes(role))
    return res.status(400).json({ error: `Rol inválido. Válidos: ${validRoles.join(', ')}` });

  if (!user_id) return res.status(400).json({ error: 'user_id requerido' });

  // Impedir que el admin se auto-degrade accidentalmente
  if (user_id === req.profile.id && role !== 'admin')
    return res.status(400).json({ error: 'No puedes cambiar tu propio rol de admin vía API' });

  const { error } = await adminDb.from('profiles').update({ role }).eq('id', user_id);
  if (error) return res.status(500).json({ error: error.message });

  // Log de auditoría en consola (en producción enviar a tabla de audit_logs)
  console.log(`[AUDIT] Admin ${req.profile.username} (${req.profile.id}) promoted user ${user_id} to ${role}`);

  res.json({ message: `Usuario promovido a "${role}" exitosamente` });
}));

// POST /admin/assign-teacher  { teacher_id, student_id }
app.post('/admin/assign-teacher', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const { teacher_id, student_id } = req.body;
  if (!teacher_id || !student_id)
    return res.status(400).json({ error: 'teacher_id y student_id son requeridos' });

  if (teacher_id === student_id)
    return res.status(400).json({ error: 'teacher_id y student_id no pueden ser iguales' });

  const { error } = await adminDb
    .from('teacher_students')
    .insert({ teacher_id, student_id });

  if (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'Asignación ya existe' });
    return res.status(400).json({ error: error.message });
  }

  res.json({ message: 'Asignación profesor→alumno creada' });
}));

// POST /admin/deactivate-user  { user_id }
app.post('/admin/deactivate-user', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const { user_id, reactivate } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id requerido' });

  if (user_id === req.profile.id)
    return res.status(400).json({ error: 'No puedes desactivar tu propia cuenta' });

  const { error } = await adminDb
    .from('profiles')
    .update({ is_active: !reactivate })
    .eq('id', user_id);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ message: reactivate ? 'Cuenta reactivada' : 'Cuenta desactivada' });
}));

// GET /admin/stats – métricas generales de la plataforma
app.get('/admin/stats', requireAuth, requireRole('admin'), asyncHandler(async (req, res) => {
  const [
    { count: totalUsers },
    { count: totalStudents },
    { count: totalTeachers },
    { count: totalGames },
  ] = await Promise.all([
    adminDb.from('profiles').select('*', { count: 'exact', head: true }),
    adminDb.from('profiles').select('*', { count: 'exact', head: true }).eq('role', 'student'),
    adminDb.from('profiles').select('*', { count: 'exact', head: true }).eq('role', 'teacher'),
    adminDb.from('scores').select('games_played', { count: 'exact', head: true }),
  ]);

  res.json({
    users: {
      total:    totalUsers,
      students: totalStudents,
      teachers: totalTeachers,
      admins:   (totalUsers || 0) - (totalStudents || 0) - (totalTeachers || 0),
    },
    total_games: totalGames,
    ts: Date.now(),
  });
}));

// ════════════════════════════════════════════════════════════════
// ERROR HANDLER GLOBAL
// Captura errores no manejados en asyncHandler
// ════════════════════════════════════════════════════════════════
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(`[ERROR] ${req.method} ${req.path}:`, err.message);
  if (IS_PRODUCTION) {
    res.status(500).json({ error: 'Error interno del servidor' });
  } else {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: `Ruta no encontrada: ${req.method} ${req.path}` });
});

// ════════════════════════════════════════════════════════════════
// START
// ════════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`🎮 EduGame API corriendo en puerto ${PORT} [${IS_PRODUCTION ? 'PRODUCTION' : 'DEVELOPMENT'}]`);
  console.log(`✅ Trust proxy: ${app.get('trust proxy')}`);
});
