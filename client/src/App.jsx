// client/src/App.jsx
import { useContext } from 'react';
import { Routes, Route, Navigate, Link } from 'react-router-dom';

import { AuthContext } from './contexts/AuthContext';
import ChatPage from './pages/ChatPage';
import LoginPage from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';

function Protected({ children }) {
  const { token } = useContext(AuthContext);
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

export default function App() {
  const { token } = useContext(AuthContext);

  return (
    <Routes>
      <Route path="/login" element={token ? <Navigate to="/chat" replace /> : <LoginPage />} />
      <Route
        path="/register"
        element={token ? <Navigate to="/chat" replace /> : <RegisterPage />}
      />
      <Route
        path="/chat"
        element={
          <Protected>
            <div style={{ padding: 24 }}>
              <p>Выберите собеседника или откройте прямую ссылку чата.</p>
              <Link to="/chat/demo">Открыть демо-чат</Link>
            </div>
          </Protected>
        }
      />
      <Route
        path="/chat/:chatId"
        element={
          <Protected>
            <ChatPage />
          </Protected>
        }
      />
      <Route path="*" element={<Navigate to={token ? '/chat' : '/login'} replace />} />
    </Routes>
  );
}
