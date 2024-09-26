const { validateForms } = require("../validations/userformsValidation");
const sendEmail = require("../helpers/sendEmail");
const validateToken = require("../validations/tokenValidation");

const UserModel = require("../models/UserModel");
const RoleModel = require("../models/RoleModel");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

async function register(req, res) {
    // user data Validation :
    const { error } = validateForms.validateRegister(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    // Checking if the user is already in the database
    const emailExists = await UserModel.findOne({ email: req.body.email });
    if (emailExists)
        return res.status(400).json({ error: "Email already exists" });

    // fetch role ObjectId
    const role = await RoleModel.findOne({ name: req.body.role });
    if (!role) return res.status(400).json({ error: "Role does not exist" });

    // Hash passwords
    const salt = await bcryptjs.genSalt(10);
    const hashedPassword = await bcryptjs.hash(req.body.password, salt);

    // Create a new user
    const user = new UserModel({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword,
        role: role._id,
    });

    try {
        const savedUser = await user.save();
        let userObject = { ...savedUser._doc };
        delete userObject.password;

        // generate a token with 6min of expiration 
        const token = jwt.sign(userObject, process.env.TOKEN_SECRET, {
            expiresIn: 600,
        });

        const queryParam = encodeURIComponent(token);
        let mailOptions = {
            from: process.env.EMAIL_USER,
            to: req.body.email,
            subject: "Account activation link",
            text: `Hello ${req.body.name},`,
            html: `
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
                    <h3>🎉 Welcome to AlloMedia! 🎉</h3>
                    <p>We're excited to have you on board. Please click the link below to activate your account:</p>
                    <a href="${process.env.FRONTEND_URL}/auth/activate?token=${queryParam}"
                       style="display: inline-block; padding: 10px 20px; margin: 20px 0; font-size: 16px; color: white; background-color: #007BFF; text-decoration: none; border-radius: 5px;">
                        🔓 Activate your account
                    </a>
                    <p>If you did not create an account, please ignore this email.</p>
                    <p>Thank you,</p>
                    <p>The AlloMedia Team</p>
                </div>
            `,
        };
        await sendEmail(mailOptions);
        res.status(201).json({
            success: "User registered successfully, verify your email",
        });
    } catch (err) {
        return res.status(400).json({ error: err.message });
    }
}

async function activate(req, res) {
    // get token from url
    const token = req.query.token;

    if (!token) return res.status(401).json({ error: "Access denied" });

    // verify token
    const decoded_user = validateToken(token);
    if (!decoded_user.success) {
        return res.status(401).json({ error: "Access denied, token invalid" });
    }
    const _id = decoded_user.data._id;
    // update user
    try {
        const updatedUser = await UserModel.updateOne(
            { _id },
            { is_verified: true }
        );
        res.json({
            success: "Account activated successfully, you can now login",
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Something went wrong" });
    }
}

module.exports = {
    register,
    activate,
};