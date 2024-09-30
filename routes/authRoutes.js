const authController = require("../controllers/AuthController");
const tokenMiddleware = require("../middlewares/tokenMiddleware");

const express = require("express");
const router = express.Router();

const rateLimit = require('express-rate-limit');

const otpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: "Too many OTP requests from this IP, please try again later."
});

router.post("/register", authController.register);
router.get("/activate", authController.activate);
router.post("/login", otpLimiter, authController.login);
router.post("/verify-otp", otpLimiter, authController.verifyOtp);
router.post("/logout", authController.logout);
router.post("/forgotpassword", otpLimiter, authController.forgotPassword);
router.post("/resetpassword/:token", tokenMiddleware, authController.resetPassword);

module.exports = router;