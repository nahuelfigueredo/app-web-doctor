import express from 'express';
import fs from 'fs';
import path from 'path';
import cors from 'cors';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_FILE = path.join(__dirname, 'turnos.json');
const MEDICO_FILE = path.join(__dirname, 'medico.json');
const JWT_SECRET = process.env.JWT_SECRET || 'cambia-este-secreto-por-uno-mas-largo-y-aleatorio';

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Crear archivos si no existen
if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(DATA_FILE, JSON.stringify([]));
}
if (!fs.existsSync(MEDICO_FILE)) {
  fs.writeFileSync(MEDICO_FILE, JSON.stringify(null));
}

function leerTurnos() {
  const data = fs.readFileSync(DATA_FILE, 'utf-8') || '[]';
  return JSON.parse(data);
}

function guardarTurnos(turnos) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(turnos, null, 2));
}

function leerMedico() {
  const data = fs.readFileSync(MEDICO_FILE, 'utf-8') || 'null';
  return JSON.parse(data); // null o { email, passwordHash }
}

function guardarMedico(medico) {
  fs.writeFileSync(MEDICO_FILE, JSON.stringify(medico, null, 2));
}

// Middleware para verificar token
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Falta Authorization header' });

  const [, token] = authHeader.split(' ');
  if (!token) return res.status(401).json({ error: 'Token ausente' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.medico = payload; // { email }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// ====== AUTH ======

// Registro inicial del médico: define email y contraseña
app.post('/api/register-medico', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email y contraseña son obligatorios' });
  }

  const medicoActual = leerMedico();
  if (medicoActual) {
    return res.status(400).json({ error: 'Ya hay un médico registrado. Usa /api/login.' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const medico = { email, passwordHash };

  guardarMedico(medico);

  return res.status(201).json({ message: 'Médico registrado correctamente. Ahora podés hacer login.' });
});

// Login del médico
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  const medico = leerMedico();
  if (!medico) {
    return res.status(400).json({ error: 'No hay médico registrado. Primero usá /api/register-medico.' });
  }

  if (medico.email !== email) {
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  }

  const ok = await bcrypt.compare(password, medico.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  }

  const token = jwt.sign({ email: medico.email }, JWT_SECRET, { expiresIn: '7d' });

  return res.json({ token });
});

// ====== ENDPOINTS DE TURNOS ======

// Crear turno (lo usa el paciente desde index.html, sin login)
app.post('/api/turnos', (req, res) => {
  const { fecha, hora, nombre, email, telefono, motivo } = req.body;

  if (!fecha || !hora || !nombre || !email || !telefono) {
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  }

  const turnos = leerTurnos();

  // Evitar doble turno misma fecha + hora (que no esté cancelado)
  const existe = turnos.some(
    t => t.fecha === fecha && t.hora === hora && t.estado !== 'cancelado'
  );
  if (existe) {
    return res.status(400).json({ error: 'Ese horario ya está ocupado' });
  }

  const nuevoTurno = {
    id: Date.now(),
    fecha,
    hora,
    nombre,
    email,
    telefono,
    motivo: motivo || '',
    estado: 'pendiente',
    creadoEn: new Date().toISOString()
  };

  turnos.push(nuevoTurno);
  guardarTurnos(turnos);

  res.status(201).json(nuevoTurno);
});

// Endpoint público para que el frontend marque horarios ocupados
app.get('/api/turnos-public', (req, res) => {
  const turnos = leerTurnos();
  const publicos = turnos.map(t => ({
    fecha: t.fecha,
    hora: t.hora,
    estado: t.estado || 'pendiente'
  }));
  res.json(publicos);
});

// Listar turnos (solo médico logueado)
app.get('/api/turnos', authMiddleware, (req, res) => {
  const turnos = leerTurnos();
  res.json(turnos);
});

// Actualizar estado (solo médico logueado)
app.patch('/api/turnos/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  const { estado } = req.body;

  const turnos = leerTurnos();
  const index = turnos.findIndex(t => t.id === Number(id));

  if (index === -1) {
    return res.status(404).json({ error: 'Turno no encontrado' });
  }

  if (estado) {
    turnos[index].estado = estado;
  }

  guardarTurnos(turnos);
  res.json(turnos[index]);
});

app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});