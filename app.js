const express = require("express");
const admin = require("firebase-admin");
const cors = require("cors");
const bodyParser = require("body-parser");
const winston = require("winston");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const bcrypt = require("bcryptjs");
require("dotenv").config();
const rateLimit = require('express-rate-limit'); 

const allowedOrigins = [ 
  'https://front-p-final-iand.vercel.app',
  'https://front-p-final-chi.vercel.app',
  'https://front-p-final-lms5.vercel.app',
  'https://front-p-final-l0liz.vercel.app',
  'http://localhost:3000'
];

const { SECRET_KEY } = process.env;
const PORT = process.env.PORT || 5002;

const limiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutos
  max: 100, // Límite por IP
  standardHeaders: true, // Headers estándar (RFC 6585)
  legacyHeaders: false, // Desactiva headers obsoletos
  skipSuccessfulRequests: false, // Cuenta todas las peticiones}
  
  handler: (req, res, next) => {
    const logData = {
      timestamp: new Date().toISOString(),
      method: req.method,
      url: req.url,
      status: res.statusCode,
      ip: req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
      server: 2,
      origin: req.get('Origin') || 'none'
    };
    
    logger.warn(logData); // Usa WARN en lugar de ERROR para límites
    db.collection("rateLimitLogs").add(logData).catch(console.error);
    
    res.status(429).json({
      error: "Too many requests",
      message: "Límite de 100 peticiones cada 10 minutos excedido",
      retryAfter: `${Math.ceil(req.rateLimit.resetTime - Date.now()) / 1000}s`
    });
  }
});


// Configuración de Firebase
let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);
} catch (error) {
  console.error('Error parsing FIREBASE_CREDENTIALS:', error);
  process.exit(1); // Salir si las credenciales son inválidas
}

// Configuración de Firebase con verificación
if (!admin.apps.length) {
  try {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    console.log('Firebase Admin inicializado correctamente');
  } catch (firebaseError) {
    console.error('Error inicializando Firebase Admin:', firebaseError);
    process.exit(1);
  }
}

const server = express();
const db = admin.firestore();
const routes = require("./routes");

server.use(bodyParser.json());
server.use(bodyParser.urlencoded({ extended: true }));
server.use(limiter);

const corsOptions = {
  origin: function (origin, callback) {
    // Permite solicitudes sin origen (como apps móviles o Postman)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`Intento de acceso desde origen no permitido: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-action-type'],
  exposedHeaders: ['Content-Length', 'X-Kuma-Revision'],
  credentials: true,
  maxAge: 86400, // Cache preflight por 24 horas
  preflightContinue: false,
  optionsSuccessStatus: 204
};

// Aplicar CORS a todas las rutas
server.use(cors(corsOptions));

// Manejar explícitamente las peticiones OPTIONS
server.options('*', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || allowedOrigins[0]);
  res.setHeader('Access-Control-Allow-Methods', corsOptions.methods.join(','));
  res.setHeader('Access-Control-Allow-Headers', corsOptions.allowedHeaders.join(','));
  res.status(corsOptions.optionsSuccessStatus).end();
});

const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: "logs/error.log", level: "error" }),
    new winston.transports.File({ filename: "logs/combined.log" })
  ],
});

// Middleware
server.use((req, res, next) => {
  // Saltar el logging para peticiones OPTIONS
  if (req.method === 'OPTIONS') return next();

  const startTime = Date.now();
  const shouldLog = ['GET', 'POST', 'PUT', 'DELETE'].includes(req.method);

  // Funciones originales
  const originalJson = res.json.bind(res);
  const originalSend = res.send.bind(res);

  const logResponse = async (body, methodUsed) => {
    const logData = {
      timestamp: new Date().toISOString(),
      method: req.method,
      url: req.url,
      status: res.statusCode,
      responseTime: Date.now() - startTime,
      ip: req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
      server: 1,
      origin: req.get('Origin') || 'none'
    };

    try {
      if (shouldLog) {
        await db.collection("logs").add(logData);
        logger[res.statusCode >= 400 ? 'error' : 'info'](logData);
      }
    } catch (error) {
      console.error("Error al guardar logs:", error);
    }

    return methodUsed(body);
  };

  res.json = (body) => logResponse(body, originalJson);
  res.send = (body) => logResponse(body, originalSend);

  next();
});

server.get('/api/cors-test', (req, res) => {
  res.json({
    message: 'CORS test successful',
    origin: req.get('Origin'),
    allowedOrigins: allowedOrigins
  });
});

// Rutas de la API
server.use("/api", routes);

// LOGIN
server.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email y contraseña son requeridos" });
    }

    const userSnapshot = await db.collection("users").where("email", "==", email).get();
    if (userSnapshot.empty) {
      return res.status(401).json({ message: "Credenciales inválidas" });
    }

    const userDoc = userSnapshot.docs[0];
    const user = userDoc.data();

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Credenciales inválidas" });
    }

    res.json({ requiresMFA: true, userId: userDoc.id });

  } catch (error) {
    logger.error("Error en login:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// OTP VERIFICATION
server.post("/verify-otp", async (req, res) => {
  try {
    const { email, token } = req.body;

    const userSnapshot = await db.collection("users").where("email", "==", email).get();
    if (userSnapshot.empty) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const user = userSnapshot.docs[0].data();
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: "base32",
      token,
      window: 1,
    });

    res.json({ success: verified });

  } catch (error) {
    logger.error("Error en verificación OTP:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// NUEVA RECUPERACIÓN CON CODIGO
server.post("/request-password-reset", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email es requerido" });
    }

    const userSnapshot = await db.collection("users").where("email", "==", email).get();
    if (userSnapshot.empty) {
      return res.status(200).json({ 
        message: "Si el email existe, podrás usar el código para restablecer tu contraseña",
        success: false 
      });
    }

    const userDoc = userSnapshot.docs[0];
    const user = userDoc.data();

    const resetToken = jwt.sign({ userId: userDoc.id }, SECRET_KEY, { expiresIn: '15m' });

    res.status(200).json({ 
      message: "Usa el código del autenticador para continuar.",
      resetToken,
      mfaSecret: user.mfaSecret,
      success: true
    });

  } catch (error) {
    console.error("Error en request-password-reset:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// RESTABLECER CONTRASEÑA
server.post("/reset-password", async (req, res) => {
  try {
    const { resetToken, mfaCode, newPassword } = req.body;

    if (!resetToken || !mfaCode || !newPassword) {
      return res.status(400).json({ message: "Todos los campos son requeridos" });
    }

    const decoded = jwt.verify(resetToken, SECRET_KEY);
    const userDoc = await db.collection("users").doc(decoded.userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const user = userDoc.data();

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: "base32",
      token: mfaCode,
      window: 1
    });

    if (!verified) {
      return res.status(401).json({ message: "Código MFA inválido" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.collection("users").doc(decoded.userId).update({ password: hashedPassword });

    res.json({ message: "Contraseña actualizada correctamente" });

  } catch (error) {
    logger.error("Error en reset-password:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// INFO DE USUARIO
server.get("/getInfo", async (req, res) => {
  try {
    const { idUs } = req.query;

    if (!idUs) {
      return res.status(400).json({ message: "ID de usuario es requerido" });
    }

    const userDoc = await db.collection("users").doc(idUs).get();

    if (!userDoc.exists) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    res.json({
      statusCode: 200,
      message: "Usuario encontrado",
      user: userDoc.data()
    });

  } catch (error) {
    logger.error("Error en getInfo:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// LOGS DEL SERVIDOR
server.get("/getServer", async (req, res) => {
  try {
    const logsSnapshot = await db.collection("logs").get();
    const logs = logsSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    res.json({
      statusCode: 200,
      message: "Logs obtenidos",
      logs
    });

  } catch (error) {
    logger.error("Error en getServer:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// ERROR CORS
server.use((err, req, res, next) => {
  if (err.message === 'Not allowed by CORS') {
    res.status(403).json({ 
      statusCode: 403,
      message: 'Origen no permitido',
      allowedOrigins,
      yourOrigin: req.headers.origin
    });
  } else {
    next(err);
  }
});

// INICIAR SERVIDOR
server.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
  console.log('Orígenes permitidos:', allowedOrigins);
});

module.exports = server;
