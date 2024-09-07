import jwt from 'jsonwebtoken';

export interface TokenData {
  userId: string;
  email: string;
}

export const generateAccessToken = (user: TokenData): string => {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: process.env.ACCESS_TOKEN_EXPIRE ?? '15m', // Access token validity (15 minutes)
  });
};

export const generateRefreshToken = (user: TokenData): string => {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRE ?? '7d', // Refresh token validity (7 days)
  });
};

export const generateEmailVerificationToken = (user: TokenData): string => {
  return jwt.sign(user, process.env.VERIFICATION_TOKEN_SECRET);
};

export const generateResetPasswordToken = (user: TokenData): string => {
  return jwt.sign(user, process.env.RESET_PASSWORD_TOKEN_SECRET, {
    expiresIn: process.env.RESET_PASSWORD_TOKEN_EXPIRE ?? '1hour', // Reset password token validity (15 minutes)
  });
};
