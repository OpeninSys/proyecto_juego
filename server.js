require('dotenv').config();
const express     = require('express');
const cors        = require('cors');
const rateLimit   = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const path        = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ════════════════════════════════════════════════════════════════
// SUPABASE CLIENTS
// supabase  → verifica tokens JWT del cliente (anon key)
// adminDb   → operaciones privilegiadas (service role, nunca al cliente)
// ════════════════════════════════════════════════════════════════
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
// MIDDLEWARE
// ════════════════════════════════════════════════════════════════
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Rate limits individuales por endpoint
const limit        = (max, windowMs = 60_000) => rateLimit({ windowMs, max, standardHeaders: true, legacyHeaders: false });
const authLimiter  = limit(10);          // registro / login: 10/min por IP
const scoreLimiter = limit(5, 10_000);  // guardar score: 5 cada 10s
const apiLimiter   = limit(120);         // resto: 120/min

app.use('/register', authLimiter);
app.use('/login',    authLimiter);
app.use('/score',    scoreLimiter);
app.use(apiLimiter);

// ════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════
function getEducationLevel(age) {
  const n = parseInt(age, 10);
  if (n >= 6  && n <= 11) return 'primaria';
  if (n >= 12 && n <= 14) return 'secundaria';
  if (n >= 15 && n <= 17) return 'preparatoria';
  if (n >= 18 && n <= 100) return 'universidad';
  return null;
}

// ════════════════════════════════════════════════════════════════
// AUTH MIDDLEWARE
// ════════════════════════════════════════════════════════════════
async function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido' });

  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) return res.status(401).json({ error: 'Token inválido o expirado' });

  const { data: profile, error: pErr } = await adminDb
    .from('profiles').select('*').eq('id', user.id).maybeSingle();

  if (pErr || !profile) return res.status(401).json({ error: 'Perfil no encontrado' });

  req.user    = user;
  req.profile = profile;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.profile?.role))
      return res.status(403).json({ error: 'Acceso denegado: rol insuficiente' });
    next();
  };
}

// ════════════════════════════════════════════════════════════════
// RUTAS PÚBLICAS
// ════════════════════════════════════════════════════════════════

app.get('/health', (_, res) => res.json({ status: 'ok', ts: Date.now() }));

// GET /subjects – lista de materias activas
app.get('/subjects', async (_, res) => {
  const { data, error } = await adminDb
    .from('subjects')
    .select('id, name, slug, description, icon')
    .eq('is_active', true)
    .order('sort_order');

  if (error) return res.status(500).json({ error: 'Error cargando materias' });
  res.json({ subjects: data });
});

// GET /leaderboard?subject_slug=&education_level=&limit=5
app.get('/leaderboard', async (req, res) => {
  const { subject_slug, education_level } = req.query;
  const safeLimit = Math.min(parseInt(req.query.limit) || 5, 100);

  // Resolver subject_id si se filtró por slug
  let subjectId = null;
  if (subject_slug) {
    const { data: sub } = await adminDb
      .from('subjects').select('id').eq('slug', subject_slug).maybeSingle();
    subjectId = sub?.id || null;
    if (!subjectId) return res.json({ leaderboard: [] });
  }

  let query = adminDb
    .from('scores')
    .select('best_score, total_xp, current_level, user_id, subject_id, subjects(name, slug, icon), profiles(username, education_level)')
    .order('best_score', { ascending: false })
    .limit(safeLimit * 3); // traer de más para poder filtrar por nivel

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
      subject:         r.subjects?.name,
      subject_icon:    r.subjects?.icon || '📚',
      best_score:      r.best_score,
      total_xp:        r.total_xp,
      level:           r.current_level
    }))
  });
});

// ════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════════════════════════════

// POST /register
app.post('/register', async (req, res) => {
  const { email, password, username, age } = req.body;

  if (!email || !password || !username || age == null)
    return res.status(400).json({ error: 'Todos los campos son obligatorios (email, password, username, age)' });

  if (password.length < 6)
    return res.status(400).json({ error: 'Contraseña mínimo 6 caracteres' });

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
    return res.status(400).json({ error: 'Username: 3–20 caracteres (letras, números o _)' });

  const education_level = getEducationLevel(age); // ← backend always decides level
  if (!education_level)
    return res.status(400).json({ error: 'Edad inválida. Rango permitido: 6–100 años' });

  // Unicidad del username
  const { data: taken } = await adminDb
    .from('profiles').select('id').eq('username', username).maybeSingle();
  if (taken) return res.status(409).json({ error: 'El username ya está en uso' });

  // Crear usuario en Supabase Auth
  const { data: auth, error: authErr } = await adminDb.auth.admin.createUser({
    email, password, email_confirm: true
  });

  if (authErr) {
    const msg = authErr.message?.toLowerCase().includes('already')
      ? 'El email ya está registrado'
      : authErr.message;
    return res.status(400).json({ error: msg });
  }

  // Crear perfil
  const { error: profileErr } = await adminDb.from('profiles').insert({
    id: auth.user.id,
    username,
    role: 'student',           // default siempre student
    age: parseInt(age, 10),
    education_level            // siempre calculado en backend
  });

  if (profileErr) {
    await adminDb.auth.admin.deleteUser(auth.user.id); // rollback
    return res.status(500).json({ error: 'Error creando perfil' });
  }

  res.status(201).json({ message: 'Cuenta creada', username, education_level });
});

// POST /login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email y contraseña requeridos' });

  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return res.status(401).json({ error: 'Credenciales inválidas' });

  const { data: profile } = await adminDb
    .from('profiles')
    .select('username, role, age, education_level')
    .eq('id', data.user.id)
    .single();

  res.json({
    token: data.session.access_token,
    user:  { id: data.user.id, email: data.user.email, ...profile }
  });
});

// ════════════════════════════════════════════════════════════════
// RUTAS AUTENTICADAS – ESTUDIANTE
// ════════════════════════════════════════════════════════════════

// GET /me
app.get('/me', requireAuth, async (req, res) => {
  const { data: scoreData } = await adminDb
    .from('scores')
    .select('best_score, total_xp, current_level, games_played, subjects(name, slug, icon)')
    .eq('user_id', req.profile.id)
    .order('total_xp', { ascending: false });

  res.json({
    id:              req.user.id,
    email:           req.user.email,
    username:        req.profile.username,
    role:            req.profile.role,
    age:             req.profile.age,
    education_level: req.profile.education_level,
    scores:          scoreData || []
  });
});

// POST /score  { subject_slug, score }
app.post('/score', requireAuth, async (req, res) => {
  const { subject_slug, score } = req.body;
  if (!subject_slug || score == null)
    return res.status(400).json({ error: 'subject_slug y score son obligatorios' });

  const parsed = parseInt(score, 10);
  if (isNaN(parsed) || parsed < 0 || parsed > 10_000)
    return res.status(400).json({ error: 'Score inválido (0–10000)' });

  // Verificar materia
  const { data: subject } = await adminDb
    .from('subjects').select('id').eq('slug', subject_slug).eq('is_active', true).maybeSingle();
  if (!subject) return res.status(404).json({ error: 'Materia no encontrada' });

  // Score actual
  const { data: current } = await adminDb
    .from('scores')
    .select('id, best_score, total_xp, games_played')
    .eq('user_id', req.profile.id)
    .eq('subject_id', subject.id)
    .maybeSingle();

  const earnedXP   = Math.max(1, Math.floor(parsed / 10));
  const newBest    = current ? Math.max(current.best_score, parsed) : parsed;
  const newXP      = (current?.total_xp     || 0) + earnedXP;
  const newGames   = (current?.games_played || 0) + 1;
  const newLevel   = Math.floor(newXP / 100) + 1;
  const isNewBest  = !current || parsed > current.best_score;

  if (current) {
    await adminDb.from('scores').update({
      best_score: newBest, total_xp: newXP,
      current_level: newLevel, games_played: newGames,
      last_played_at: new Date().toISOString()
    }).eq('id', current.id);
  } else {
    await adminDb.from('scores').insert({
      user_id: req.profile.id, subject_id: subject.id,
      best_score: parsed, total_xp: earnedXP,
      current_level: 1, games_played: 1
    });
  }

  res.json({
    message:     isNewBest ? '¡Nuevo récord personal!' : 'Score guardado',
    best_score:  newBest,
    total_xp:    newXP,
    level:       newLevel,
    earned_xp:   earnedXP,
    is_new_best: isNewBest
  });
});

// ════════════════════════════════════════════════════════════════
// RUTAS AUTENTICADAS – PROFESOR
// ════════════════════════════════════════════════════════════════

// GET /teacher/students?subject_slug=&education_level=
app.get('/teacher/students', requireAuth, requireRole('teacher', 'admin'), async (req, res) => {
  const { subject_slug, education_level } = req.query;

  // IDs de alumnos asignados a este profesor
  const { data: relations, error: relErr } = await adminDb
    .from('teacher_students')
    .select('student_id')
    .eq('teacher_id', req.profile.id);

  if (relErr)   return res.status(500).json({ error: 'Error obteniendo relaciones' });
  if (!relations?.length) return res.json({ students: [], total: 0 });

  const studentIds = relations.map(r => r.student_id);

  // Perfiles de alumnos (con filtro opcional por nivel)
  let profileQ = adminDb
    .from('profiles')
    .select('id, username, age, education_level, created_at')
    .in('id', studentIds);
  if (education_level) profileQ = profileQ.eq('education_level', education_level);

  const { data: students, error: studErr } = await profileQ;
  if (studErr) return res.status(500).json({ error: 'Error obteniendo estudiantes' });

  // Resolver subject_id para filtrar scores
  let subjectId = null;
  if (subject_slug) {
    const { data: sub } = await adminDb
      .from('subjects').select('id').eq('slug', subject_slug).maybeSingle();
    subjectId = sub?.id || null;
  }

  // Scores de todos los alumnos
  let scoreQ = adminDb
    .from('scores')
    .select('user_id, best_score, total_xp, current_level, games_played, subjects(name, slug, icon)')
    .in('user_id', studentIds);
  if (subjectId) scoreQ = scoreQ.eq('subject_id', subjectId);

  const { data: allScores } = await scoreQ;

  // Ensamblar resultado
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
        games_played: sc.games_played
      })),
      total_xp:     scores.reduce((s, sc) => s + sc.total_xp,   0),
      best_overall: scores.reduce((m, sc) => Math.max(m, sc.best_score), 0)
    };
  });

  result.sort((a, b) => b.total_xp - a.total_xp);
  res.json({ students: result, total: result.length });
});

// GET /teacher/leaderboard?subject_slug=
app.get('/teacher/leaderboard', requireAuth, requireRole('teacher', 'admin'), async (req, res) => {
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
    .select('best_score, total_xp, current_level, user_id, subjects(name, slug, icon), profiles(username, education_level)')
    .in('user_id', studentIds)
    .order('best_score', { ascending: false })
    .limit(50);

  if (subjectId) query = query.eq('subject_id', subjectId);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: 'Error cargando ranking' });

  res.json({
    leaderboard: (data || []).map((r, i) => ({
      rank:            i + 1,
      username:        r.profiles?.username || '???',
      education_level: r.profiles?.education_level,
      subject:         r.subjects?.name,
      subject_icon:    r.subjects?.icon || '📚',
      best_score:      r.best_score,
      total_xp:        r.total_xp,
      level:           r.current_level
    }))
  });
});

// ════════════════════════════════════════════════════════════════
// RUTAS ADMIN
// ════════════════════════════════════════════════════════════════

// POST /admin/promote  { user_id, role, override_key }
// Solo para operaciones internas – NUNCA exponer en frontend
app.post('/admin/promote', async (req, res) => {
  const { user_id, role, override_key } = req.body;

  if (!override_key || override_key !== process.env.ADMIN_OVERRIDE_KEY)
    return res.status(403).json({ error: 'Clave de override inválida' });

  const validRoles = ['student', 'teacher', 'admin', 'school_admin'];
  if (!validRoles.includes(role))
    return res.status(400).json({ error: `Rol inválido. Válidos: ${validRoles.join(', ')}` });

  const { error } = await adminDb.from('profiles').update({ role }).eq('id', user_id);
  if (error) return res.status(500).json({ error: error.message });

  res.json({ message: `Usuario promovido a "${role}" exitosamente` });
});

// POST /admin/assign-teacher  { teacher_id, student_id }
app.post('/admin/assign-teacher', requireAuth, requireRole('admin'), async (req, res) => {
  const { teacher_id, student_id } = req.body;
  if (!teacher_id || !student_id)
    return res.status(400).json({ error: 'teacher_id y student_id son requeridos' });

  const { error } = await adminDb
    .from('teacher_students').insert({ teacher_id, student_id });

  if (error) return res.status(400).json({ error: error.message });
  res.json({ message: 'Asignación profesor→alumno creada' });
});

// ════════════════════════════════════════════════════════════════
// START
// ════════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`🎮 EduGame API corriendo en puerto ${PORT}`);
});