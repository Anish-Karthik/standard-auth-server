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
  generateRefreshToken,
} from '@/utils/auth/generate-token';
import {
  verifyAccessToken,
  verifyRefreshToken,
} from '@/utils/auth/verify-token';

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

      const user = await prisma.user.create({
        data: { email, password: hashedPassword },
      });

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
      // Create JWT token
      const accessToken = generateAccessToken({
        userId: user.id,
        email: user.email,
      });
      const refreshToken = generateRefreshToken({
        userId: user.id,
        email: user.email,
      });

      // Send refresh token in an HttpOnly cookie for security
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
}
