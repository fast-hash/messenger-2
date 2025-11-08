// Socket.IO authentication: on failure -> immediate disconnect
import { wireWsMetrics, incWsAuthFailed } from '../metrics.js';
import { verifyAccess, ensureActiveUserSession } from '../middleware/auth.js';

export function socketAuth(io) {
  wireWsMetrics(io);
  // первичная проверка при рукопожатии
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake?.auth?.token || '';
      const user = verifyAccess(token);
      await ensureActiveUserSession(user);
      socket.data.user = user;
      next();
    } catch {
      incWsAuthFailed();
      next(new Error('AUTH_FAILED'));
    }
  });

  // дополнительная защита: если что-то пойдет не так в процессе
  io.on('connection', (socket) => {
    socket.use(async (_packet, next) => {
      try {
        const token = socket.handshake?.auth?.token || '';
        const user = verifyAccess(token);
        await ensureActiveUserSession(user);
        socket.data.user = user;
        next();
      } catch {
        incWsAuthFailed();
        socket.emit('error', 'AUTH_FAILED');
        socket.disconnect(true);
      }
    });
  });
}
