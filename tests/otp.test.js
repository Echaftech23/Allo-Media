const request = require('supertest');
const app = require('../app');
const mongoose = require("mongoose");
const UserModel = require('../models/UserModel');
const RoleModel = require('../models/RoleModel');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');

// Mock the sendEmail function
jest.mock('../helpers/sendEmailHelper', () => ({
    sendEmail: jest.fn()
}));

const { sendEmail } = require("../helpers/sendEmailHelper");

describe('POST /auth/login', () => {
    let clientRoleId;
    let userId;

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

        // Create a test user with lastLogin date older than 30 days
        const hashedPassword = await bcryptjs.hash('Echafai@echafai2021', 10);
        const user = await UserModel.create({
            name: "Echafai Rachid",
            email: "echfaiechafai20221@gmail.com",
            password: hashedPassword,
            role: clientRoleId,
            is_verified: true,
            lastLogin: new Date(Date.now() - 40 * 24 * 60 * 60 * 1000) // 40 days ago
        });
        userId = user._id;
    });

    afterAll(async () => {
        await mongoose.connection.collection('users').drop();
        await mongoose.connection.close();
    });

    it('should send OTP if last login was more than 30 days ago', async () => {
        const loginData = {
            email: "echfaiechafai20221@gmail.com",
            password: "Echafai@echafai2021"
        };
        const response = await request(app)
            .post('/auth/login')
            .send(loginData)
            .set('Accept', 'application/json');

        expect(response.statusCode).toBe(200);
        expect(response.body).toHaveProperty('success', 'OTP sent to your email');
        expect(response.body).toHaveProperty('otpToken');
        expect(sendEmail).toHaveBeenCalled();
    });

    it('should verify OTP and log in the user', async () => {
        // Generate OTP and OTP token
        const otp = speakeasy.totp({
            secret: process.env.OTP_SECRET,
            encoding: 'base32',
            step: 300
        });

        const otpToken = jwt.sign({
            userId: userId,
            otpGeneratedAt: Date.now()
        }, process.env.OTP_TOKEN_SECRET, { expiresIn: '5m' });

        const verifyOtpData = {
            otp: otp,
            otpToken: otpToken
        };

        const response = await request(app)
            .post('/auth/verify-otp')
            .send(verifyOtpData)
            .set('Accept', 'application/json');

        expect(response.statusCode).toBe(200);
        expect(response.body).toHaveProperty('success', 'Logged in successfully');
        expect(response.body).toHaveProperty('user');
    });

    it('should return 400 if OTP token is missing', async () => {
        const verifyOtpData = {
            otp: '123456'
        };

        const response = await request(app)
            .post('/auth/verify-otp')
            .send(verifyOtpData)
            .set('Accept', 'application/json');

        expect(response.statusCode).toBe(400);
        expect(response.body).toHaveProperty('error', 'OTP token is required');
    });

    it('should return 400 if OTP token is invalid or expired', async () => {
        const verifyOtpData = {
            otp: '123456',
            otpToken: 'invalidToken'
        };

        const response = await request(app)
            .post('/auth/verify-otp')
            .send(verifyOtpData)
            .set('Accept', 'application/json');

        expect(response.statusCode).toBe(400);
        expect(response.body).toHaveProperty('error', 'Invalid or expired OTP token');
    });

    it('should return 400 if OTP is invalid', async () => {
        // Generate OTP token
        const otpToken = jwt.sign({
            userId: userId,
            otpGeneratedAt: Date.now()
        }, process.env.OTP_TOKEN_SECRET, { expiresIn: '5m' });

        const verifyOtpData = {
            otp: 'invalidOtp',
            otpToken: otpToken
        };

        const response = await request(app)
            .post('/auth/verify-otp')
            .send(verifyOtpData)
            .set('Accept', 'application/json');

        expect(response.statusCode).toBe(400);
        expect(response.body).toHaveProperty('error', 'Invalid OTP');
    });

});