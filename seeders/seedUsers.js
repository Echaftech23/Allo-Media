const bcrypt = require('bcryptjs');
const User = require('../models/UserModel');
const Role = require('../models/RoleModel');

async function seedUsers() {
    try {
        // Fetch roles from the database to get their ObjectIds
        const superAdminRole = await Role.findOne({ name: 'superAdmin' });
        const clientRole = await Role.findOne({ name: 'client' });
        const deliveryRole = await Role.findOne({ name: 'delivery' });
        const managerRole = await Role.findOne({ name: 'manager' });

        if (!superAdminRole || !clientRole || !deliveryRole || !managerRole) {
            console.error('Roles not found, make sure roles are seeded first.');
            return;
        }

        const users = [
            {
                name: 'Manager',
                email: 'manager@gmail.com',
                password: await bcrypt.hash('123456', 10),
                role: managerRole._id, // Assign role ObjectId
                is_verified: false
            },
            {
                name: 'Client',
                email: 'client@gmail.com',
                password: await bcrypt.hash('123456', 10),
                role: clientRole._id, // Assign role ObjectId
                is_verified: true
            },
            {
                name: 'Delivery',
                email: 'delivery@gmail.com',
                password: await bcrypt.hash('123456', 10),
                role: deliveryRole._id, // Assign role ObjectId
                is_verified: true
            },
            {
                name: 'SuperAdmin',
                email: 'superadmin@gmail.com',
                password: await bcrypt.hash('123456', 10),
                role: superAdminRole._id, // Assign role ObjectId
                is_verified: true
            }
        ];

        // Check if users already exist to avoid duplicates
        const existingUsers = await User.find();
        if (existingUsers.length === 0) {
            // Insert users if none exist
            await User.insertMany(users);
            console.log('Users seeded successfully!');
        } else {
            console.log('Users already exist, no seeding required.');
        }
    } catch (error) {
        console.error('Error seeding users:', error);
    }
}

module.exports = seedUsers;
