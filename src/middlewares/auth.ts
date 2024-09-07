import { type NextFunction, type Request, type Response } from 'express';
import prisma from '@/lib/prisma';
import { verifyAccessToken } from '@/utils/auth/verify-token';

export const verifyAuthToken = async (
  // Remove underscore of params once you start using them
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (req.headers.authorization?.startsWith('Bearer')) {
    try {
      const token = req.headers.authorization.split(' ')[1]; // Extract token from header
      const decoded = verifyAccessToken(token); // Verify token

      // Attach the user to the request object
      req.user = await prisma.user.findUnique({
        where: { id: decoded.userId },
        select: { id: true, email: true, name: true },
      });

      if (!req.user) {
        return res.status(401).json({ message: 'Not authorized' });
      }

      next();
    } catch (error) {
      return res.status(401).json({ message: 'Not authorized, token failed' });
    }
  } else {
    return res.status(401).json({ message: 'Not authorized, no token' });
  }
};
