const express = require("express");
const router = express.Router();
const { Signup, Login, VerifyEmail, RefreshToken } = require("../controllers/authController");

router.post("/signup", Signup);
router.get("/verify-email", VerifyEmail);
router.post("/login", Login);
router.post("/refresh-token", RefreshToken);


module.exports = router;