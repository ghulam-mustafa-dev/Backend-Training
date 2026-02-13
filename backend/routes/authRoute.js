const express = require("express");
const { Signup, Login, VerifyEmail } = require("../controllers/authController");
const router = express.Router();

router.post("/signup", Signup);
router.post("/login", Login);
router.get("/verify-email", VerifyEmail);


module.exports = router;