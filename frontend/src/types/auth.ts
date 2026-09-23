export interface User {
  id: string;
  username: string;
  email: string;
  roles: string[];
  permissions?: string[];
  is_active: boolean;
  email_alerts_enabled?: boolean;
  last_login?: string | null;
}

export interface LoginCredentials {
  username_or_email: string;
  password: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface UserMeResponse {
  id: string;
  username: string;
  email: string;
  roles: string[];
  permissions: string[];
  is_active: boolean;
  email_alerts_enabled?: boolean;
  last_login?: string | null;
}
