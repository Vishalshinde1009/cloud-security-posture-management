import React, { createContext, useContext, useState, useEffect } from 'react';
import api from '../services/api';
import { User, LoginCredentials, AuthResponse, UserMeResponse } from '../types/auth';

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => Promise<void>;
  hasRole: (role: string | string[]) => boolean;
  hasPermission: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(() => {
    const cachedUser = sessionStorage.getItem('cspm_user');
    return cachedUser ? JSON.parse(cachedUser) : null;
  });
  const [token, setToken] = useState<string | null>(() => {
    return sessionStorage.getItem('cspm_access_token');
  });
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const verifySession = async () => {
      if (token) {
        try {
          const res = await api.get<UserMeResponse>('/auth/me');
          setUser(res.data);
          sessionStorage.setItem('cspm_user', JSON.stringify(res.data));
        } catch {
          setUser(null);
          setToken(null);
          sessionStorage.removeItem('cspm_access_token');
          sessionStorage.removeItem('cspm_user');
        }
      }
      setIsLoading(false);
    };

    verifySession();
  }, [token]);

  const login = async (credentials: LoginCredentials) => {
    setIsLoading(true);
    try {
      const res = await api.post<AuthResponse>('/auth/login', credentials);
      const { access_token } = res.data;


      setToken(access_token);
      sessionStorage.setItem('cspm_access_token', access_token);

      // Fetch complete user profile with permissions
      const meRes = await api.get<UserMeResponse>('/auth/me', {
        headers: { Authorization: `Bearer ${access_token}` },
      });

      setUser(meRes.data);
      sessionStorage.setItem('cspm_user', JSON.stringify(meRes.data));
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    try {
      if (token) {
        await api.post('/auth/logout');
      }
    } catch {
      // Ignore network errors on logout
    } finally {
      setUser(null);
      setToken(null);
      sessionStorage.removeItem('cspm_access_token');
      sessionStorage.removeItem('cspm_user');
      window.location.href = '/login';
    }
  };

  const hasRole = (role: string | string[]): boolean => {
    if (!user || !user.roles) return false;
    const allowed = Array.isArray(role) ? role : [role];
    return user.roles.some((r) => allowed.includes(r));
  };

  const hasPermission = (permission: string): boolean => {
    if (!user || !user.permissions) return false;
    return user.permissions.includes(permission);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!token && !!user,
        isLoading,
        login,
        logout,
        hasRole,
        hasPermission,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
