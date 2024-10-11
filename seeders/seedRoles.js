const Role = require('../models/roleModel'); 

async function seedRoles() {
    const roles = [
        { name: 'superAdmin' },
        { name: 'client' },
        { name: 'delivery' },
        { name: 'manager' }
    ];

    try {
        // Check if roles already exist to avoid duplicates
        const existingRoles = await Role.find();
        if (existingRoles.length === 0) {
            // Insert roles if none exist
            await Role.insertMany(roles);
            console.log('Roles seeded successfully!');
        } else {
            console.log('Roles already exist, no seeding required.');
        }
    } catch (error) {
        console.error('Error seeding roles:', error);
    }
}

seedRoles();

module.exports = seedRoles;