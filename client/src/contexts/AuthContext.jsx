import { jwtDecode } from 'jwt-decode';
import React, { createContext, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { api } from '../api/api';
import { clearAccessToken, getAccessToken, setAccessToken } from '../api/request.js';
import { resetSignalState } from '../crypto/signal';

export const AuthContext = createContext();

const TOKEN_CLOCK_SKEW_SEC = 5;

function decodeAccessToken(token) {
  if (!token) {
    return null;
  }
  try {
    const payload = jwtDecode(token);
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp === 'number' && payload.exp <= now) {
      return null;
    }
    if (typeof payload.nbf === 'number' && payload.nbf > now + TOKEN_CLOCK_SKEW_SEC) {
      return null;
    }
    return payload;
  } catch (err) {
    console.warn('Failed to decode access token', err);
    return null;
  }
}

function getUserIdFromPayload(payload) {
  if (!payload || typeof payload !== 'object') {
    return null;
  }
  return payload.userId || payload.sub || payload.id || null;
}

export function AuthProvider({ children }) {
  const initialSession = useMemo(() => {
    const storedToken = getAccessToken();
    const payload = decodeAccessToken(storedToken);
    const resolvedUserId = getUserIdFromPayload(payload);
    if (!storedToken || !payload || !resolvedUserId) {
      clearAccessToken();
      return { token: null, userId: null };
    }
    return { token: storedToken, userId: resolvedUserId };
  }, []);
  const [token, setToken] = useState(initialSession.token);
  const [userId, setUserId] = useState(initialSession.userId);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const setSession = (nextToken, explicitUserId) => {
    if (!nextToken) {
      clearAccessToken();
      setToken(null);
      setUserId(null);
      return null;
    }

    const payload = decodeAccessToken(nextToken);
    if (!payload) {
      throw new Error('Invalid or expired access token received');
    }

    const resolvedUserId = explicitUserId ?? getUserIdFromPayload(payload);
    if (!resolvedUserId) {
      throw new Error('Access token is missing a user identifier');
    }

    setAccessToken(nextToken);
    setToken(nextToken);
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
