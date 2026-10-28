import React, { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { api, setAccessToken, type AuthUser } from "@/lib/api";
import { hasPermission, type Permission, type UserRole } from "@shared/auth";
import { toast } from "sonner";

interface AuthContextType {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: { email: string; password: string }) => Promise<void>;
  register: (payload: { email: string; password: string; fullName: string }) => Promise<void>;
  logout: () => Promise<void>;
  checkPermission: (permission: Permission) => boolean;
  hasRole: (roles: UserRole[]) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Restore session on application mount via HttpOnly refresh cookie
  useEffect(() => {
    let isMounted = true;

    async function restoreSession() {
      try {
        const res = await api.refresh();
        if (isMounted && res.user && res.accessToken) {
          setAccessToken(res.accessToken);
          setUser(res.user);
        }
      } catch {
        // No active or valid session, remain unauthenticated
        if (isMounted) {
          setAccessToken(null);
          setUser(null);
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    }

    restoreSession();

    return () => {
      isMounted = false;
    };
  }, []);

  const login = async (credentials: { email: string; password: string }) => {
    const res = await api.login(credentials);
    setAccessToken(res.accessToken);
    setUser(res.user);
    toast.success(`Welcome back, ${res.user.fullName} (${res.user.role})`);
  };

  const register = async (payload: { email: string; password: string; fullName: string }) => {
    const res = await api.register(payload);
    setAccessToken(res.accessToken);
    setUser(res.user);
    toast.success(`Account created successfully as ${res.user.role}`);
  };

  const logout = async () => {
    try {
      await api.logout();
    } catch (err) {
      console.warn("Logout error:", err);
    } finally {
      setAccessToken(null);
      setUser(null);
      toast.info("You have been signed out.");
    }
  };

  const checkPermission = (permission: Permission): boolean => {
    if (!user) return false;
    return hasPermission(user.role, permission);
  };

  const hasRole = (roles: UserRole[]): boolean => {
    if (!user) return false;
    return roles.includes(user.role);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
        checkPermission,
        hasRole,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
