const express = require("express");
const { Signup, Login, VerifyEmail } = require("../controllers/authController");
const router = express.Router();

router.post("/signup", Signup);
router.get("/verify-email", VerifyEmail);
router.post("/login", Login);


module.exports = router;