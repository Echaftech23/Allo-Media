const request = require('supertest');
const app = require('../app');
const mongoose = require("mongoose");
const UserModel = require('../models/userModel');
const RoleModel = require('../models/roleModel');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Mock the sendEmail function
jest.mock('../helpers/sendEmailHelper', () => ({
    sendEmail: jest.fn()
}));

const { sendEmail } = require("../helpers/sendEmailHelper");

describe('AuthController', () => {
    let clientRoleId;
    let userId;
    let token;

    beforeAll(async () => {
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });

        // Ensure roles exist in the database
        const clientRole = await RoleModel.findOne({ name: 'client' });
        if (!clientRole) {
            const newRole = new RoleModel({ name: 'client' });
            await newRole.save();
            clientRoleId = newRole._id;
        } else {
            clientRoleId = clientRole._id;
        }

        // Create a test user
        const hashedPassword = await bcryptjs.hash('Echafai@echafai2021', 10);
        const user = await UserModel.create({
            name: "Echafai Rachid",
            email: "echfaiechafai20221@gmail.com",
            password: hashedPassword,
            role: clientRoleId,
            is_verified: true
        });
        userId = user._id;

        // Generate a token for resetPassword test
        token = jwt.sign({ _id: user._id, name: user.name, email: user.email, role: user.role.name }, process.env.TOKEN_SECRET, { expiresIn: 600 });
    });

    afterAll(async () => {
        await mongoose.connection.collection('users').drop();
        await mongoose.connection.close();
    });

    describe('POST /auth/forgot-password', () => {
        it('should send a password reset email if the user exists', async () => {

            const response = await request(app)
                .post('/auth/forgot-password')
                .send({ email: "echfaiechafai20221@gmail.com" })
                .set('Accept', 'application/json');

            expect(response.statusCode).toBe(200);
            expect(response.body).toHaveProperty('success', 'Check your email to reset your password!!');
            expect(sendEmail).toHaveBeenCalled();
        });

        it('should return 400 if the email is not found', async () => {

            const response = await request(app)
                .post('/auth/forgot-password')
                .send({ email: "nonexistent@example.com" })
                .set('Accept', 'application/json');

            expect(response.statusCode).toBe(400);
            expect(response.body).toHaveProperty('error', 'Email is not found');
        });
    });

    describe('POST /auth/reset-password/:token', () => {
        it('should reset the password if the token is valid', async () => {
            const newPassword = 'NewPassword@2021';

            const response = await request(app)
                .post(`/auth/reset-password/${token}`)
                .send({ password: newPassword, confirmPassword: newPassword })
                .set('Accept', 'application/json');
    
            expect(response.statusCode).toBe(200);
            expect(response.body).toHaveProperty('success', 'Password reset successfully');
    
            // Verify that the password was updated
            const user = await UserModel.findById(userId);
            const isMatch = await bcryptjs.compare(newPassword, user.password);
            expect(isMatch).toBe(true);
        });
    
        it('should return 400 if the password is invalid', async () => {

            const response = await request(app)
                .post(`/auth/reset-password/${token}`)
                .send({ password: 'short', confirmPassword: 'short' })
                .set('Accept', 'application/json');
    
            expect(response.statusCode).toBe(400);
            expect(response.body).toHaveProperty('error');
        });
    });
});