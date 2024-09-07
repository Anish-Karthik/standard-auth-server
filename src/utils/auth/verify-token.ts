import jwt, { type JwtPayload } from 'jsonwebtoken';

export const verifyAccessToken = (token: string) => {
  return jwt.verify(token, process.env.ACCESS_TOKEN_SECRET) as JwtPayload;
};

export const verifyRefreshToken = (token: string) => {
  return jwt.verify(token, process.env.REFRESH_TOKEN_SECRET) as JwtPayload;
};

export const verifyEmailVerificationToken = (token: string) => {
  return jwt.verify(token, process.env.VERIFICATION_TOKEN_SECRET) as JwtPayload;
};

export const verifyResetPasswordToken = (token: string) => {
  return jwt.verify(
    token,
    process.env.RESET_PASSWORD_TOKEN_SECRET
  ) as JwtPayload;
};
