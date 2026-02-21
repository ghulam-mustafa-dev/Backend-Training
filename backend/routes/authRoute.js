const express = require("express");
const router = express.Router();
const { Signup, Login, VerifyEmail, RefreshToken, ForgotPassword, VerifyPasswordToken, NewPasswordForm, Logout } = require("../controllers/authController");

router.post("/signup", Signup);
router.get("/verify-email", VerifyEmail);
router.post("/login", Login);
router.post("/refresh-token", RefreshToken);
router.post("/forgot-password", ForgotPassword);
router.get("/verify-password-token", VerifyPasswordToken);
router.post("/new-password-form", NewPasswordForm);
router.post("/logout", Logout);


module.exports = router;