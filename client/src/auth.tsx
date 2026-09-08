import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';

export const API = (import.meta.env.VITE_API_URL ?? 'http://localhost:4000/api').replace(/\/$/, '');
export type Role = 'FIELD_OPERATOR' | 'SUPERVISOR';
export type AuthUser = { id: string; operatorId: string; name: string; role: Role };
type AuthContextValue = { user: AuthUser | null; loading: boolean; sessionMessage: string; login: (operatorId: string, password: string) => Promise<void>; logout: () => Promise<void>; hasRole: (role: Role) => boolean };
const AuthContext = createContext<AuthContextValue | null>(null);

export async function request(path: string, options: RequestInit = {}) {
  const token = localStorage.getItem('fieldverify-token');
  const headers = new Headers(options.headers);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`${API}${path}`, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401) {
    localStorage.removeItem('fieldverify-token');
    localStorage.removeItem('fieldverify-user');
    throw new Error(data.error ?? 'Your session has expired. Please log in again.');
  }
  if (!response.ok) throw new Error(data.error ?? 'Request failed');
  return data;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [sessionMessage, setSessionMessage] = useState('');
  useEffect(() => { const token = localStorage.getItem('fieldverify-token'); if (!token) { setLoading(false); return; } request('/auth/me').then((next) => { setUser(next); localStorage.setItem('fieldverify-user', JSON.stringify(next)); }).catch((error) => { setUser(null); setSessionMessage(error.message); }).finally(() => setLoading(false)); }, []);
  const login = async (operatorId: string, password: string) => { const data = await request('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ operatorId, password }) }); localStorage.setItem('fieldverify-token', data.token); localStorage.setItem('fieldverify-user', JSON.stringify(data.user)); setSessionMessage(''); setUser(data.user); };
  const logout = async () => { try { await request('/auth/logout', { method: 'POST' }); } finally { localStorage.removeItem('fieldverify-token'); localStorage.removeItem('fieldverify-user'); setUser(null); window.history.replaceState({}, '', '/login'); } };
  return <AuthContext.Provider value={{ user, loading, sessionMessage, login, logout, hasRole: (role) => user?.role === role }}>{children}</AuthContext.Provider>;
}
export function useAuth() { const context = useContext(AuthContext); if (!context) throw new Error('useAuth must be used inside AuthProvider'); return context; }
