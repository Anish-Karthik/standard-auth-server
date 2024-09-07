import { Router } from 'express';
import { body, validationResult } from 'express-validator';
import Controller from './users.controller';
import { CreateUserDto } from '@/dto/user.dto';
import RequestValidator from '@/middlewares/request-validator';
import { checkAdmin, verifyAuthToken } from '@/middlewares/auth';

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

const users: Router = Router();
const controller = new Controller();

/**
 * Create user body
 * @typedef {object} CreateUserBody
 * @property {string} email.required - email of user
 * @property {string} name.required - name of user
 * @property {string} cognitoId.required - cognito id
 * @property {string} phone - phone number
 */
/**
 * User
 * @typedef {object} User
 * @property {string} email - email of user
 * @property {string} name - name of user
 * @property {string} cognitoId - cognito id
 * @property {string} phone - phone number
 */
/**
 * POST /users/create
 * @summary Create user
 * @tags users
 * @param {CreateUserBody} request.body.required
 * @return {User} 201 - user created
 */
users.post(
  '/',
  verifyAuthToken,
  RequestValidator.validate(CreateUserDto),
  controller.createUser
);

users.post(
  '/create-many',
  verifyAuthToken,
  checkAdmin,
  [
    body('users').isArray().withMessage('Users must be an array'),
    body('users.*.email').isEmail().withMessage('Invalid email format'),
  ],
  validate,
  controller.createManyUsers
);

export default users;
