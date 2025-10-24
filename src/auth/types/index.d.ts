export interface RegisterInputTypes {
  email: string;
  password: string;
  name?: string;
}

export interface LoginInputTypes {
  email: string;
  password: string;
}

export interface ResetPasswordInputTypes {
  newPassword: string;
  token: string;
}
