import { jwtDecode } from 'jwt-decode';
import React, { createContext, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { api } from '../api/api';
import { clearAccessToken, getAccessToken, setAccessToken } from '../api/request.js';
import { resetSignalState } from '../crypto/signal';

export const AuthContext = createContext();

function extractUserId(token) {
  if (!token) {
    return null;
  }
  try {
    const payload = jwtDecode(token);
    return payload?.userId || payload?.sub || null;
  } catch (err) {
    console.warn('Failed to decode access token', err);
    return null;
  }
}

export function AuthProvider({ children }) {
  const initialToken = useMemo(() => getAccessToken(), []);
  const [token, setToken] = useState(initialToken);
  const [userId, setUserId] = useState(() => extractUserId(initialToken));
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const setSession = (nextToken, explicitUserId) => {
    setAccessToken(nextToken);
    setToken(nextToken);
    const resolvedUserId = explicitUserId ?? extractUserId(nextToken);
    setUserId(resolvedUserId);
    return resolvedUserId;
  };

  const login = async (creds) => {
    setError('');
    const { token: issuedToken, userId: issuedUserId } = await api.login(creds);
    return setSession(issuedToken, issuedUserId);
  };

  const register = async (data) => {
    setError('');
    const { token: issuedToken, userId: issuedUserId } = await api.register(data);
    return setSession(issuedToken, issuedUserId);
  };

  const logout = () => {
    clearAccessToken();
    setToken(null);
    setUserId(null);
    resetSignalState();
    navigate('/login');
  };

  return (
    <AuthContext.Provider value={{ token, userId, error, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
