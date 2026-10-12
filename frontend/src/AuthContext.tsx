import React, { createContext, useContext, useEffect, useState } from 'react';
import { api, setCsrfToken } from './api/client';
import { SessionInfo } from './api/types';

interface AuthState {
  session: SessionInfo | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  stepUp: (password: string) => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthState>(null as unknown as AuthState);
export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    try {
      const me = await api<SessionInfo>('/api/auth/me');
      setCsrfToken(me.csrfToken);
      setSession(me);
    } catch {
      setSession(null);
      setCsrfToken(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    const onUnauth = () => {
      setSession(null);
      setCsrfToken(null);
    };
    window.addEventListener('rbac-ui:unauthenticated', onUnauth);
    return () => window.removeEventListener('rbac-ui:unauthenticated', onUnauth);
  }, []);

  const login = async (username: string, password: string) => {
    const resp = await api<{ username: string; role: SessionInfo['role']; csrfToken: string }>(
      '/api/auth/login', { method: 'POST', body: { username, password } });
    setCsrfToken(resp.csrfToken);
    await refresh();
  };

  const logout = async () => {
    try {
      await api('/api/auth/logout', { method: 'POST' });
    } finally {
      setSession(null);
      setCsrfToken(null);
    }
  };

  const stepUp = async (password: string) => {
    await api('/api/auth/step-up', { method: 'POST', body: { password } });
    await refresh();
  };

  return (
    <AuthContext.Provider value={{ session, loading, login, logout, stepUp, refresh }}>
      {children}
    </AuthContext.Provider>
  );
}
