const authController = require("../controllers/AuthController");

const express = require("express");
const router = express.Router();

router.post("/register", authController.register);
router.get("/activate", authController.activate);
router.post("/login", authController.login);
router.post("/verify-otp", authController.verifyOtp);
router.post("/logout", authController.logout);
// router.post("forgotpassword", authController.forgotPassword);

module.exports = router;