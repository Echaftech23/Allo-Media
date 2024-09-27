const { validateForms } = require("../validations/userformsValidation");
const sendEmail = require("../helpers/sendEmailHelper");
const sendVerificationEmail = require("../helpers/emailTemplateHelper");
const validateToken = require("../validations/tokenValidation");

const UserModel = require("../models/UserModel");
const RoleModel = require("../models/RoleModel");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
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
        await sendVerificationEmail(savedUser, req.body.email, req.body.name);

        res.status(201).json({
            success: "User registered successfully, verify your email",
        });
    } catch (err) {
        return res.status(400).json({ error: err.message });
    }
}

async function login(req, res) {
    const { error } = validateForms.validateLogin(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    // Checking if the user exists
    const user = await UserModel.findOne({ email: req.body.email }).populate(
        "role"
    );

    if (!user) return res.status(400).json({ error: "Email is not found" });

    // Checking if the password is correct
    const validPass = await bcryptjs.compare(req.body.password, user.password);
    if (!validPass) return res.status(400).json({ error: "Invalid password" });

    // checking if the user is verified
    if (!user.is_verified) {
        await sendVerificationEmail(user, req.body.email, user.name);
        return res.status(401).json({ error: "Please verify your email. A new verification email has been sent." });
    }

    // Generate OTP :
    const otp = speakeasy.totp({
        secret: process.env.OTP_SECRET,
        encoding: 'base32',
        expiresIn: 400,
    });

    // Send OTP via email
    let mailOptions = {
        from: process.env.EMAIL_USER,
        to: req.body.email,
        subject: "Your OTP Code",
        text: `Your OTP code is ${otp}`,
        html: `<p>Your OTP code is <strong>${otp}</strong></p>`
    };
    await sendEmail(mailOptions);

    // Save OTP in user session or database (for demonstration, we'll use session)
    req.session.otp = otp;
    req.session.user = user;

    res.status(200).json({ success: "OTP sent to your email" });

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

async function verifyOtp(req, res) {
    const { otp } = req.body;

    // Check if OTP is valid
    const isValid = speakeasy.totp.verify({
        secret: process.env.OTP_SECRET,
        encoding: 'base32',
        token: otp,
        window: 1
    });

    if (!isValid) {
        return res.status(400).json({ error: "Invalid OTP" });
    }

    // Retrieve user from session
    const user = req.session.user;

    // Create and assign a token
    const token = jwt.sign({ user }, process.env.TOKEN_SECRET);

    const returnUser = {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role.name,
    };

    // Set token in cookie
    res.cookie("authToken", token, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
    });

    // Clear OTP and user from session
    req.session.otp = null;
    req.session.user = null;

    res.json({ success: "Logged in successfully", user: returnUser });
}

function logout(req, res) {
    req.user = null;
    req.cookies["authToken"] = null;
    res.cookie("authToken", "", {
        httpOnly: true,
        secure: true,
        sameSite: "none",
    });
    res.json({ success: "Logged out successfully" });
}

module.exports = {
    register,
    login,
    activate,
    verifyOtp,
    logout,
};