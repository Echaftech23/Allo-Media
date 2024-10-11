const request = require('supertest');
const app = require('../app');
const mongoose = require("mongoose"); 
const UserModel = require('../models/userModel');
const RoleModel = require('../models/roleModel');
const bcryptjs = require('bcryptjs');

// Mock the sendVerificationEmail function
jest.mock('../helpers/emailTemplateHelper', () => ({
    sendVerificationEmail: jest.fn()
}));

const { sendVerificationEmail } = require("../helpers/emailTemplateHelper");

describe('POST /auth/login', () => {
    let clientRoleId;

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
            is_verified: true,
            lastLogin: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000)

        });

        await UserModel.create({
            name: "John Doe",
            email: "johndoe@example.com",
            password: hashedPassword,
            role: clientRoleId,
            is_verified: false,
            lastLogin: new Date()
        });

    });

    afterAll(async () => {
        await mongoose.connection.collection('users').drop();
        await mongoose.connection.close();
    });

    it('should return 200 OK and login the user', async () => {
        const loginData = {
            email: "echfaiechafai20221@gmail.com",
            password: "Echafai@echafai2021"
        };
        const response = await request(app)
            .post('/auth/login')
            .send(loginData)
            .set('Accept', 'application/json');

        expect(response.statusCode).toBe(200);
        expect(response.body).toHaveProperty(['token']);
    });

    it('should return 400 Bad Request if the email is invalid', async () => {
        const loginData = {
            email: "echfaiechafai202/21@gmail.com",
            password: "Echafai@echafai2021"
        };
        const response = await request(app)
            .post('/auth/login')
            .send(loginData)
            .set('Accept', 'application/json');

        expect(response.statusCode).toBe(400);
        expect(response.body.error).toBe("Invalid email or password");
    });

    it('should return 400 Bad Request if the password is invalid', async () => {
        const loginData = {
            email: "echfaiechafai20221@gmail.com",
            password: "Echafasi@echafai2021"
        };

        const response = await request(app)
            .post('/auth/login')
            .send(loginData)
            .set('Accept', 'application/json');

        expect(response.statusCode).toBe(400);
        expect(response.body.error).toBe("Invalid email or password");

    });

    it('should return 401 Unauthorized if the user is not verified', async () => {

        sendVerificationEmail.mockResolvedValue({ success: true });

        const loginData = {
            email: "johndoe@example.com",
            password: "Echafai@echafai2021"
        };

        const response = await request(app)
            .post('/auth/login')
            .send(loginData)
            .set('Accept', 'application/json');
        
        expect(response.statusCode).toBe(401);
        expect(response.body.error).toBe("Please verify your email. A new verification email has been sent.");
    });

});