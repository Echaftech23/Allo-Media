const validateForms = require("../validations/userformsValidation");
const sendMail = require("../helpers/sendMail");
const validateToken = require("../validations/tokenValidation");

const UserModel = require("../models/UserModel");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

async function register(req, res) {
    // console.log(req.body);
    // Validate the data before we make a user
    const { error } = validateForms.validateRegister(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    // Checking if the user is already in the database
    const emailExists = await UserModel.findOne({ email: req.body.email });
    if (emailExists)
        return res.status(400).json({ error: "Email already exists" });

    // Hash passwords
    const salt = await bcryptjs.genSalt(10);
    const hashedPassword = await bcryptjs.hash(req.body.password, salt);

    let payload = {
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        role: req.body.role,
    };

    // Create a new user
    const user = new UserModel({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword,
        role: req.body.role,
    });
    try {
        const savedUser = await user.save();
        let userObject = { ...savedUser._doc };
        delete userObject.password;

        // generate a token with 600 seconds of expiration
        const token = jwt.sign(userObject, process.env.TOKEN_SECRET, {
            expiresIn: 600,
        });
        const queryParam = encodeURIComponent(token);
        let mailOptions = {
            from: "AlloMedia.livraieon@media.com",
            to: req.body.email,
            subject: "Account activation link",
            text: `Hello ${req.body.name},`,
            html: `<h3> Please click on the link to activate your account </h3>
        <a href="http://127.0.0.1:5173/activate?token=${queryParam}">Activate your account</a>`,
        };
        await sendMail(mailOptions); // send email to user

        res.status(201).json({
            success: "User registered successfully, verify your email",
        });
    } catch (err) {
        return res.status(400).send(err);
    }
}

async function activate(req, res) {
    // get token from url
    const token = req.body.token;
    if (!token) return res.status(401).json({ error: "Access denied" });
    // verify token
    const decoded_user = validateToken(token);
    if (!decoded_user.success) {
        return res.status(401).json({ error: "Access denied, token unvalid" });
    }

    const _id = decoded_user.data._id;
    // update user
    try {
        const updatedUser = await UserModel.updateOne(
            { _id },
            { is_verified: true }
        );
        res.json({
            success: "Account activated successfully, now go to log in",
        });
    } catch (e) {
        console.log(e);
        res.status(400).json({ error: "Something went wrong" });
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
    if (!user.is_verified)
        return res.status(401).json({ error: "Please verify your email" });

    // Create and assign a token
    const token = jwt.sign({ user }, process.env.TOKEN_SECRET);

    const returnUser = {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role.name,
    };

    // res.header('auth-token', token);
    res.cookie("authToken", token, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
    });

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

async function forgotPassword(req, res) {
    const { error } = validateForms.validateEmail(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    // Checking if the user exists
    const user = await UserModel.findOne({ email: req.body.email }).populate(
        "role"
    );
    if (!user) return res.status(400).json({ error: "Email is not found" });

    try {
        let payload = {
            _id: user._id,
            name: user.name,
            email: user.email,
            role: user.role.name,
        };

        // generate a token with 600 seconds of expiration
        const token = jwt.sign(payload, process.env.TOKEN_SECRET, {
            expiresIn: 600,
        });
        // generate a token with 600 seconds of expiration
        let mailOptions = {
            from: "AlloMedia.livraieon@media.com",
            to: req.body.email,
            subject: "Retrieve your password",
            text: `Hello ${req.body.name},`,
            html: `<h3> Please click on the link to reset your password </h3>
        <a href="http://127.0.0.1:5173/resetpassword?token=${token}">
        Reset your password</a>`,
        };
        sendMail(mailOptions);

        res.json({ success: "Check your email to reset your password!!!!!!" });
    } catch (e) {
        console.log(e);
        res.status(400).json({ error: "Something went wrong" });
    }
}

async function resetPassword(req, res) {
    console.log("resetPassword");
    const user = req.user;
    const { error } = validateForms.validatePassword(req.body);

    if (error) {
        return res.status(400).json({ error: error.details[0].message });
    }

    try {
        // Generate a salt
        const salt = await bcryptjs.genSalt(10);

        // Hash the new password with the generated salt
        const hashedPassword = await bcryptjs.hash(req.body.password, salt);

        // Update the user's password
        const updatedUser = await UserModel.updateOne(
            { _id: user._id },
            { password: hashedPassword }
        );
    } catch (e) {
        console.log(e);
        return res.status(400).json({ error: "Something went wrong" });
    }

    res.json({ success: "Password reset successfully" });
}

function checkAuth(req, res) {
    let user = req.user;
    let returnUser = {
        _id: user.user._id,
        name: user.user.name,
        email: user.user.email,
        role: user.user.role.name,
    };
    res.json({ success: "user is Already logged in hhhh", user: returnUser });
}

module.exports = {
    register,
    activate,
    login,
    logout,
    forgotPassword,
    resetPassword,
    checkAuth,
};