const request = require('supertest');
const app = require('../app');
const mongoose = require("mongoose");
const UserModel = require('../models/userModel');
const RoleModel = require('../models/roleModel');
const bcryptjs = require('bcryptjs');

describe('POST /auth/register', () => {
    beforeAll(async () => {
        await mongoose.connect(process.env.MONGODB_URI);

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
        await UserModel.create({
            name: "Echafai Rachid",
            email: "echfaiechafai2021@gmail.com",
            password: hashedPassword,
            role: clientRoleId,
            is_verified: true,
            lastLogin: new Date()
        });
    });

    afterAll(async () => {
        await mongoose.connection.collection('users').drop();
        await mongoose.connection.close();
    });

    it('should return 201 OK and register a new user', async () => {
        const userData = {
            name: "Echafai Rachid",
            email: "echfaiechafai2023@gmail.com",
            password: "Echafai-2021",
            confirmPassword: "Echafai-2021",
            role: "client"
        };
        const response = await request(app)
            .post('/auth/register')
            .send(userData)
            .set('Accept', 'application/json');

        expect(response.statusCode).toBe(201);
        expect(response.body.success).toBe("User registered successfully, verify your email");
    });

    // it('should return 400 Bad Request if the user already exists', async () => {
    //     const userData = {
    //         name: "Echafai Rachid",
    //         email: "echfaiechafai2023@gmail.com",
    //         password: "Echafai-2021",
    //         confirmPassword: "Echafai-2021",
    //         role: "client"
    //     };
    //     const response = await request(app)
    //         .post('/auth/register')
    //         .send(userData)
    //         .set('Accept', 'application/json');
        
    //     expect(response.statusCode).toBe(400);
    //     expect(response.body.error).toBe("Email already exists");
    // });

    it('should return 400 if role does not exist', async () => {
        const userData = {
            name: "Echafai Rachid",
            email: "echfaiechafai2022@gmail.com",
            password: "Echafai-2021",
            confirmPassword: "Echafai-2021",
            role: "nonexistentrole"
        };
        const res = await request(app)
            .post('/auth/register')
            .send(userData)
            .set('Accept', 'application/json');

        expect(res.statusCode).toBe(400);
        expect(res.body.error).toBe("Role does not exist");
    });

});