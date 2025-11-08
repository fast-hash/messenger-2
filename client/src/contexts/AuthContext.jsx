import React, { createContext, useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { api } from '../api/api';
import { resetSignalState } from '../crypto/signal';

export const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [userId, setUserId] = useState(null);
  const [error, setError] = useState('');
  const [initialised, setInitialised] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const session = await api.session();
        if (!cancelled && session?.userId) {
          setUserId(session.userId);
        }
      } catch (err) {
        if (!cancelled) {
          console.warn('Failed to restore session', err);
          setUserId(null);
        }
      } finally {
        if (!cancelled) {
          setInitialised(true);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (creds) => {
    setError('');
    try {
      const { userId: issuedUserId } = await api.login(creds);
      setUserId(issuedUserId);
      setInitialised(true);
      return issuedUserId;
    } catch (err) {
      setError('Не удалось выполнить вход.');
      throw err;
    }
  }, []);

  const register = useCallback(async (data) => {
    setError('');
    try {
      const { userId: issuedUserId } = await api.register(data);
      setUserId(issuedUserId);
      setInitialised(true);
      return issuedUserId;
    } catch (err) {
      setError('Не удалось завершить регистрацию.');
      throw err;
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch (err) {
      console.warn('Failed to call logout endpoint', err);
    } finally {
      setUserId(null);
      resetSignalState();
      navigate('/login');
    }
  }, [navigate]);

  const value = useMemo(
    () => ({
      userId,
      isAuthenticated: Boolean(userId),
      error,
      login,
      register,
      logout,
      initialised,
    }),
    [userId, error, login, register, logout, initialised]
  );

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}
