const bcrypt = require("bcryptjs");
const User = require("../models/userModel");
const Role = require("../models/roleModel");

async function seedUsers() {
  try {
    // Fetch roles from the database to get their ObjectIds
    const superAdminRole = await Role.findOne({ name: "superAdmin" });
    const clientRole = await Role.findOne({ name: "client" });
    const deliveryRole = await Role.findOne({ name: "delivery" });
    const managerRole = await Role.findOne({ name: "manager" });

    if (!superAdminRole || !clientRole || !deliveryRole || !managerRole) {
      console.error("Roles not found, make sure roles are seeded first.");
      return;
    }

    const users = [
      {
        name: "Manager",
        email: "manager@gmail.com",
        password: await bcrypt.hash("123456", 10),
        role: managerRole._id, // Assign role ObjectId
        is_verified: false,
        lastLogin: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
      },
      {
        name: "Client",
        email: "client@gmail.com",
        password: await bcrypt.hash("123456", 10),
        role: clientRole._id, // Assign role ObjectId
        is_verified: true,
        lastLogin: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
      },
      {
        name: "Delivery",
        email: "delivery@gmail.com",
        password: await bcrypt.hash("123456", 10),
        role: deliveryRole._id, // Assign role ObjectId
        is_verified: true,
        lastLogin: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
      },
      {
        name: "SuperAdmin",
        email: "superadmin@gmail.com",
        password: await bcrypt.hash("123456", 10),
        role: superAdminRole._id, // Assign role ObjectId
        is_verified: true,
        lastLogin: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
      },
    ];

    // Check if users already exist to avoid duplicates
    const existingUsers = await User.find();
    if (existingUsers.length === 0) {
      // Insert users if none exist
      await User.insertMany(users);
      console.log("Users seeded successfully!");
    } else {
      console.log("Users already exist, no seeding required.");
    }
  } catch (error) {
    console.error("Error seeding users:", error);
  }
}

seedUsers();

module.exports = seedUsers;
