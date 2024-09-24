import { Router } from 'express';
import csurf from 'csurf';
import { body, validationResult } from 'express-validator';
import AuthController from './auth.controller';

const router = Router();
const authController = new AuthController();

const csrfProtection = csurf({ cookie: true });

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

router.post(
  '/register',
  [
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').isLength({ min: 6 }).withMessage('Password too short'),
  ],
  validate,
  authController.register
);
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').isLength({ min: 6 }).withMessage('Password too short'),
  ],
  validate,
  authController.login
);
router.post('/refresh-token', csrfProtection, authController.refreshToken);
router.post('/logout', authController.logout);
router.post('/verify', authController.verify);

router.post('/send-verification-email', authController.sendVerificationEmail);
router.post('/verify-email', authController.verifyEmail);

router.post('/forgot-password', authController.sendForgotPasswordMail);
router.post('/reset-password', authController.resetPassword);

export default router;
