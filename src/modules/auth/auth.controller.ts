import { type NextFunction, type Request } from 'express';
import { type User } from '@prisma/client';
import { HttpStatusCode } from 'axios';
import bcrypt from 'bcryptjs';
import UserService from '../users/users.service';
import { type CustomResponse } from '@/types/common.type';
import Api from '@/lib/api';
import prisma from '@/lib/prisma';
import {
  generateAccessToken,
  generateEmailVerificationToken,
  generateRefreshToken,
  generateResetPasswordToken,
} from '@/utils/auth/generate-token';
import {
  verifyAccessToken,
  verifyRefreshToken,
  verifyResetPasswordToken,
} from '@/utils/auth/verify-token';
import { sendVerificationEmail } from '@/lib/email-service';

export default class AuthController extends Api {
  private readonly userService = new UserService();
  public register = async (
    req: Request,
    res: CustomResponse<User>,
    next: NextFunction
  ) => {
    try {
      const { email, password } = req.body;
      const userExists = await prisma.user.findUnique({
        where: { email },
      });
      if (userExists) {
        return this.send(
          res,
          null,
          HttpStatusCode.Conflict,
          'User already exists'
        );
      }
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 12);
      let verified = false;
      if (
        process.env.ALLOW_AUTO_VERIFY === 'true' &&
        req.query.autoverify === 'true'
      ) {
        verified = true;
      }
      const user = await prisma.user.create({
        data: { email, password: hashedPassword, verified },
      });

      if (!verified && process.env.AUTO_VERIFY_EMAIL === 'false') {
        // Send verification email
        await sendVerificationEmail(
          user,
          generateEmailVerificationToken({
            userId: user.id,
            email: user.email,
          }),
          req.query.redirect as string
        );
      }

      return this.send(res, user, HttpStatusCode.Created, 'User Registered');
    } catch (e) {
      next(e);
    }
  };

  public login = async (
    req: Request,
    res: CustomResponse<User>,
    next: NextFunction
  ) => {
    try {
      const { email, password } = req.body;
      const user = await prisma.user.findUnique({
        where: { email },
      });
      if (!user) {
        return this.send(res, null, HttpStatusCode.NotFound, 'User not found');
      }
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        return this.send(
          res,
          null,
          HttpStatusCode.BadRequest,
          'Invalid password'
        );
      }
      // Send refresh token in an HttpOnly cookie for security
      if (user.mfaEnabled) {
        // Implement MFA here
      }
      // Create JWT token
      const accessToken = generateAccessToken({
        userId: user.id,
        email: user.email,
      });
      const refreshToken = generateRefreshToken({
        userId: user.id,
        email: user.email,
      });
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
      });
      return this.send(res, { accessToken }, HttpStatusCode.Ok, 'Logged in');
    } catch (e) {
      next(e);
    }
  };

  public logout = async (
    req: Request,
    res: CustomResponse<User>,
    next: NextFunction
  ) => {
    try {
      res.clearCookie('refreshToken');
      return this.send(res, null, HttpStatusCode.Ok, 'Logged out');
    } catch (e) {
      next(e);
    }
  };

  public refreshToken = async (
    req: Request,
    res: CustomResponse<User>,
    next: NextFunction
  ) => {
    try {
      const { refreshToken } = req.cookies;
      if (!refreshToken) {
        return this.send(
          res,
          null,
          HttpStatusCode.BadRequest,
          'No refresh token found'
        );
      }
      const decoded = verifyRefreshToken(refreshToken);
      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
      });

      if (!user) {
        return this.send(res, null, HttpStatusCode.NotFound, 'User not found');
      }

      const accessToken = generateAccessToken({
        userId: user.id,
        email: user.email,
      });
      return this.send(
        res,
        { accessToken },
        HttpStatusCode.Ok,
        'Token refreshed'
      );
    } catch (e) {
      next(e);
    }
  };

  public verify = async (
    req: Request,
    res: CustomResponse<User>,
    next: NextFunction
  ) => {
    try {
      const { accessToken } = req.body;
      const decoded = verifyAccessToken(accessToken);
      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
      });

      if (!user) {
        return this.send(res, null, HttpStatusCode.NotFound, 'User not found');
      }

      return this.send(res, user, HttpStatusCode.Ok, 'User verified');
    } catch (e) {
      next(e);
    }
  };

  public verifyEmail = async (
    req: Request,
    res: CustomResponse<User>,
    next: NextFunction
  ) => {
    try {
      const { token } = req.query;
      if (!token) {
        return this.send(
          res,
          null,
          HttpStatusCode.BadRequest,
          'No verification token found'
        );
      }
      const decoded = verifyAccessToken(token as string);
      if (!decoded.userId) {
        return this.send(
          res,
          null,
          HttpStatusCode.BadRequest,
          'Invalid verification token'
        );
      }
      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
      });

      if (!user) {
        return this.send(res, null, HttpStatusCode.NotFound, 'User not found');
      }

      await prisma.user.update({
        where: { id: user.id },
        data: { verified: true },
      });

      return this.send(res, user, HttpStatusCode.Ok, 'Email verified');
    } catch (e) {
      next(e);
    }
  };

  public forgotPassword = async (
    req: Request,
    res: CustomResponse<User>,
    next: NextFunction
  ) => {
    try {
      const { email } = req.body;
      const user = await prisma.user.findUnique({
        where: { email },
      });

      if (!user) {
        return this.send(res, null, HttpStatusCode.NotFound, 'User not found');
      }

      const resetToken = generateResetPasswordToken({
        userId: user.id,
        email: user.email,
      });

      // Send reset password email
      await sendVerificationEmail(
        user,
        resetToken,
        req.query.redirect as string
      );

      return this.send(
        res,
        null,
        HttpStatusCode.Ok,
        'Reset password email sent'
      );
    } catch (e) {
      next(e);
    }
  };

  public resetPassword = async (
    req: Request,
    res: CustomResponse<User>,
    next: NextFunction
  ) => {
    try {
      const { token, password } = req.body;
      if (!token) {
        return this.send(
          res,
          null,
          HttpStatusCode.BadRequest,
          'No verification token found'
        );
      }
      const decoded = verifyResetPasswordToken(token);
      if (!decoded.userId) {
        return this.send(
          res,
          null,
          HttpStatusCode.BadRequest,
          'Invalid verification token'
        );
      }
      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
      });

      if (!user) {
        return this.send(res, null, HttpStatusCode.NotFound, 'User not found');
      }

      const hashedPassword = await bcrypt.hash(password, 12);

      await prisma.user.update({
        where: { id: user.id },
        data: { password: hashedPassword },
      });

      return this.send(res, null, HttpStatusCode.Ok, 'Password reset');
    } catch (e) {
      next(e);
    }
  };

  public verifyMfa = async (
    req: Request,
    res: CustomResponse<User>,
    next: NextFunction
  ) => {
    try {
      // to be implemented
    } catch (e) {
      next(e);
    }
  };
}
