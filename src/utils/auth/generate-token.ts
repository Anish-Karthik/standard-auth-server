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
