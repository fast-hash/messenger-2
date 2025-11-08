import http from 'node:http';

import cors from 'cors';
import express from 'express';
import expressRateLimit from 'express-rate-limit';
import helmet from 'helmet';
import mongoose from 'mongoose';
import morgan from 'morgan';
import { Server as SocketIOServer } from 'socket.io';

import config from './config.js';
import { requestIdLogger } from './logger.js';
import { httpMetrics, metricsHandler, wireWsMetrics, incWsAuthFailed } from './metrics.js';
import authMiddleware, { verifyJwt, getSharedSecret } from './middleware/auth.js';
import Chat from './models/Chat.js';
import authRouter from './routes/auth.js';
import buildKeybundleRouter from './routes/keybundle.js';
import messagesRouter from './routes/messages.js';
import { mountTestBootstrap } from './test/bootstrap.routes.js';

export async function connectMongo(uri) {
  const configuredUri =
    uri ?? process.env.MONGO_URL ?? (config.has('mongo.uri') ? config.get('mongo.uri') : undefined);
  if (!configuredUri) {
    throw new Error('MONGO_URL not configured');
  }
  await mongoose.connect(configuredUri);
}

const OBJECT_ID_RE = /^[a-f\d]{24}$/i;
const REAUTH_WINDOW_MS = 60_000;
const REAUTH_MAX_ATTEMPTS = 5;

export function createApp({
  authMiddleware: overrideAuth,
  audit,
  logger = console,
  messageObserver,
  onMessage,
} = {}) {
  const app = express();
  app.locals.logger = logger;

  const auditStream = {
    write: (str) => {
      const line = str.endsWith('\n') ? str.slice(0, -1) : str;
      if (audit) {
        audit(line);
      } else {
        logger.info?.(line) ?? logger.log?.(line);
      }
    },
  };

  app.use(requestIdLogger);
  app.use(httpMetrics);

  app.use(
    helmet({
      // Базовые заголовки безопасности
      hsts: { maxAge: 15552000, includeSubDomains: false },
      referrerPolicy: { policy: 'no-referrer' },
      crossOriginOpenerPolicy: { policy: 'same-origin' },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      // Строгая CSP без unsafe-*; worker + ws/wss разрешены
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          'default-src': ["'self'"],
          'base-uri': ["'none'"],
          'frame-ancestors': ["'none'"],
          'object-src': ["'none'"],
          'script-src': ["'self'"],
          'style-src': ["'self'"],
          'img-src': ["'self'", 'data:'],
          'font-src': ["'self'", 'data:'],
          'connect-src': ["'self'", 'ws:', 'wss:'],
          'worker-src': ["'self'", 'blob:'],
          'manifest-src': ["'self'"],
          'form-action': ["'self'"],
        },
      },
    })
  );
  app.use((_, res, next) => {
    res.setHeader(
      'Permissions-Policy',
      'accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), usb=()'
    );
    next();
  });
  app.use(cors({ origin: config.get('server.cors.origins'), credentials: true }));
  app.use(express.json({ limit: config.get('server.jsonLimit'), strict: true }));
  app.use(morgan('tiny', { stream: auditStream }));
  app.use(expressRateLimit({ windowMs: 60_000, max: 300 }));

  const pass = (req, _res, next) => next();
  const auth = overrideAuth || authMiddleware || pass;

  if (!overrideAuth) {
    try {
      getSharedSecret();
    } catch (err) {
      logger.error?.('jwt_secret_validation_failed', err);
      const error = new Error('JWT shared secret misconfigured');
      error.cause = err;
      throw error;
    }
  }

  const perUserLimiter = expressRateLimit({
    windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000),
    max: Number(process.env.RATE_LIMIT_MAX || 120),
    keyGenerator: (req) => req.user?.id || req.ip,
    standardHeaders: true,
    legacyHeaders: false,
  });

  app.use('/api/auth', authRouter);

  app.use('/api/keybundle', buildKeybundleRouter(auth));

  const messagesMiddlewares = [auth, perUserLimiter];
  if (typeof messageObserver === 'function') {
    messagesMiddlewares.push((req, _res, next) => {
      try {
        messageObserver(req.body);
      } catch (err) {
        logger.error?.('messageObserver_failed', err);
      }
      next();
    });
  }
  messagesMiddlewares.push(messagesRouter({ auth: null, onMessage }));
  app.use('/api/messages', ...messagesMiddlewares);

  app.get('/healthz', (_req, res) => {
    res.status(200).json({ ok: true });
  });

  app.get('/metrics', metricsHandler);

  mountTestBootstrap(app);

  app.get('/', (_req, res) => {
    res.send('Secure Messenger API');
  });

  app.use((err, _req, res, _next) => {
    logger.error?.('Unhandled error:', err);
    res.status(500).json({ error: 'internal_error' });
  });

  return app;
}

function verifySocketToken(token, { audience, issuer }) {
  const payload = verifyJwt(token, {
    audience,
    issuer,
  });
  const userId = payload.sub || payload.userId || payload.id;
  if (!userId) {
    throw new Error('unauthorized');
  }
  return userId.toString();
}

export function attachSockets(server, { cors: corsOptions } = {}) {
  const allowedOriginsEnv = process.env.SOCKET_ALLOWED_ORIGINS;
  const allowedOrigins = allowedOriginsEnv
    ? allowedOriginsEnv
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean)
    : config.get('server.cors.origins');

  const io = new SocketIOServer(server, {
    cors: {
      origin: corsOptions?.origin ?? allowedOrigins,
      credentials: true,
    },
  });

  wireWsMetrics(io);

  const audience = process.env.JWT_AUDIENCE || undefined;
  const issuer = process.env.JWT_ISSUER || undefined;

  io.use((socket, next) => {
    try {
      const header = socket.handshake.headers?.authorization;
      const tokenFromHeader =
        typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7) : undefined;
      const token = tokenFromHeader || socket.handshake.auth?.token;
      if (!token) {
        incWsAuthFailed();
        return next(new Error('unauthorized'));
      }

      const userId = verifySocketToken(token, { audience, issuer });
      socket.data.user = { id: userId };
      socket.data.reauthAttempts = [];
      return next();
    } catch {
      incWsAuthFailed();
      return next(new Error('unauthorized'));
    }
  });

  io.on('connection', (socket) => {
    socket.on('join', async ({ chatId } = {}, ack) => {
      try {
        if (typeof chatId !== 'string' || !OBJECT_ID_RE.test(chatId)) {
          throw new Error('bad chatId');
        }
        const ok = await Chat.isMember(chatId, socket.data?.user?.id);
        if (!ok) {
          throw new Error('forbidden');
        }
        await socket.join(chatId);
        ack?.({ ok: true });
      } catch (err) {
        ack?.({ ok: false, error: err.message });
      }
    });

    socket.on('reauth', async ({ accessToken } = {}, ack) => {
      try {
        const now = Date.now();
        const attempts = Array.isArray(socket.data.reauthAttempts)
          ? socket.data.reauthAttempts.filter((ts) => now - ts <= REAUTH_WINDOW_MS)
          : [];
        if (attempts.length >= REAUTH_MAX_ATTEMPTS) {
          throw new Error('rate_limited');
        }
        if (typeof accessToken !== 'string' || !accessToken) {
          throw new Error('invalid_token');
        }
        attempts.push(now);
        socket.data.reauthAttempts = attempts;

        const nextUserId = verifySocketToken(accessToken, { audience, issuer });
        socket.data.user = { id: nextUserId };

        const rooms = [...socket.rooms].filter((room) => room !== socket.id);
        await Promise.all(
          rooms.map(async (room) => {
            const member = await Chat.isMember(room, nextUserId);
            if (!member) {
              await socket.leave(room);
            }
          })
        );

        ack?.({ ok: true });
      } catch (err) {
        ack?.({ ok: false, error: err.message || 'unauthorized' });
      }
    });
  });

  return io;
}

export async function attachHttp(app, options = {}) {
  const server = http.createServer(app);
  const io = attachSockets(server, options.io);
  return { app, server, io };
}
