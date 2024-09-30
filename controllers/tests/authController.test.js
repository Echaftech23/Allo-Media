const { register, activate } = require('../AuthController');
const { validateForms } = require("../../validations/userformsValidation");
const sendEmail = require("../../helpers/sendEmail");
const validateToken = require("../../validations/tokenValidation");
const UserModel = require("../../models/UserModel");
const RoleModel = require("../../models/RoleModel");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Mocking dependencies
jest.mock('../../validations/userformsValidation');
jest.mock('../../helpers/sendEmail');
jest.mock('../../validations/tokenValidation');
jest.mock('../../models/UserModel');
jest.mock('../../models/RoleModel');
jest.mock('bcryptjs');
jest.mock('jsonwebtoken');

describe('Auth Controller', () => {
  let mockRequest;
  let mockResponse;

  beforeEach(() => {
    mockRequest = {
      body: {
        name: 'Test User',
        email: 'test@example.com',
        password: 'password123',
        role: 'client'
      },
      query: {}
    };
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
  });

  describe('register', () => {
    it('should register a new user successfully', async () => {
      // Mock successful validations and database operations
      validateForms.validateRegister.mockReturnValue({ error: null });
      UserModel.findOne.mockResolvedValue(null);
      RoleModel.findOne.mockResolvedValue({ _id: 'role123' });
      bcryptjs.genSalt.mockResolvedValue('salt');
      bcryptjs.hash.mockResolvedValue('hashedPassword');
      UserModel.prototype.save.mockResolvedValue({
        _doc: { _id: 'user123', name: 'Test User', email: 'test@example.com', role: 'role123' }
      });
      jwt.sign.mockReturnValue('testtoken');

      await register(mockRequest, mockResponse);

      expect(mockResponse.status).toHaveBeenCalledWith(201);
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: "User registered successfully, verify your email"
      });
      expect(sendEmail).toHaveBeenCalled();
    });

    it('should return 400 if validation fails', async () => {
      validateForms.validateRegister.mockReturnValue({ error: { details: [{ message: 'Validation error' }] } });

      await register(mockRequest, mockResponse);

      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: 'Validation error' });
    });
  });

  describe('activate', () => {
    it('should activate a user account successfully', async () => {
      mockRequest.query.token = 'validtoken';
      validateToken.mockReturnValue({ success: true, data: { _id: 'user123' } });
      UserModel.updateOne.mockResolvedValue({ nModified: 1 });

      await activate(mockRequest, mockResponse);

      expect(mockResponse.json).toHaveBeenCalledWith({
        success: "Account activated successfully, you can now login"
      });
    });

    it('should return 401 if token is missing', async () => {
      await activate(mockRequest, mockResponse);

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: "Access denied" });
    });

    it('should return 401 if token is invalid', async () => {
      mockRequest.query.token = 'invalidtoken';
      validateToken.mockReturnValue({ success: false });

      await activate(mockRequest, mockResponse);

      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({ error: "Access denied, token invalid" });
    });
  });

});