const User = require("../models/userModel");
const PasswordResets = require("../models/PasswordResetModel");
const bcrypt = require("bcrypt");
const { z, ZodError, includes } = require("zod");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { sendVerificationEmail, sendForgotPasswordEmail } = require("../utils/emailVerification");
const { generateAccessToken, generateRefreshToken } = require("../utils/jwt");
const e = require("express");


const Signup = async (req, res) => {
    try{
        const { name, email, password } = req.body;
        const userSchema = z.object({
            name: z.string().min(3, "Name must be atleast 3 characters"),
            email: z.string().email("Invalid email address"),
            password: z.string().min(8, "Password must be atleast 8 characters"),
        });
        const validatedData = userSchema.parse({ name, email, password });

        const saltRounds = Number(process.env.SALT_ROUNDS);
        const hashedPassword = await bcrypt.hash(validatedData.password, saltRounds);

        const email_verificationToken = crypto.randomBytes(32).toString("hex");
        const email_verificationExpires = new Date(Date.now() + 60 * 60 * 1000);
        const url = process.env.FRONTEND_BASE_URL;
// i dont have frontend page with specific route thats why i sent backend route in email
        const emailVerificationUrl = `${url}/api/auth/verify-email?token=${email_verificationToken}`;

        const user = await User.create({
            name: validatedData.name,
            email: validatedData.email,
            password: hashedPassword,
            is_verified: false,
            email_verification_token: email_verificationToken,
            email_verification_expires: email_verificationExpires
        });

        await sendVerificationEmail(validatedData.email, validatedData.name, emailVerificationUrl);
        
        return res.status(201).json({message: "User Registered Successfully"});
    } 
    catch(error){
        if(error instanceof ZodError){
            const formattedErrors = error.issues.map((issue) => ({
                field: issue.path[0],
                message: issue.message
            }));
            return res.status(400).json({errors: formattedErrors });
        }
        return res.status(500).json({error: "An error occurred while registering user"});
    }
}

const VerifyEmail = async (req, res) => {
    try{
        const { token } = req.query;
        const user = await User.findOne({
            where: {
                email_verification_token: token
            }
        });
        if(!user){
            return res.status(400).json({error: "Invalid Token"});
        }
        if(user.email_verification_expires < new Date()){
            return res.status(400).json({error: "Token Expired"});
        }
        user.is_verified = true;
        user.email_verification_token = null;
        user.email_verification_expires = null;
        await user.save();

        return res.status(200).json({message: "Email Verified Successfully"});
    }
    catch(error){
        return res.status(500).json({error: "An error occurred while verifying email"});
    }
}

const Login = async (req, res) => {
    try{
        const { email, password } = req.body;
        const userSchema = z.object({
            email: z.string().email("Invalid email address"),
            password: z.string().min(8, "Password must be atleast 8 characters"),
        });
        const validatedData = userSchema.parse({ email, password });

        const user = await User.findOne({
            where: {
                email: validatedData.email
            }
        });
        if(!user){
            return res.status(401).json({error: "Invalid credentials"});
        }
        const checkPassword = await bcrypt.compare(validatedData.password, user.password);
        if(!checkPassword){
            return res.status(401).json({error: "Invalid credentials"});
        }
        
        if(!user.is_verified){
            return res.status(403).json({error: "Email is not verified"});
        }

        const payload = {
            id: user.id,
            name: user.name,
            email: user.email
        }
        const access_token = generateAccessToken(payload);

        const refresh_token = generateRefreshToken(payload);

        res.cookie("__Secure-at", access_token, {
            maxAge: 15 * 60 * 1000,
            httpOnly: true,
            secure: false,
            sameSite: "strict"
        });
        res.cookie("__Secure-rt", refresh_token, {
            maxAge: 90 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: false,
            sameSite: "strict",
        });
        return res.status(200).json({ message: "Login Successful" });
    }
    catch(error){
        if(error instanceof ZodError){
            const formattedErrors = error.issues.map((issue) => ({
                field: issue.path[0],
                message: issue.message
            }));
            return res.status(400).json({ errors: formattedErrors });
        }
        return res.status(500).json({error: "An error occurred while login"});
    }
}

const RefreshToken = async (req, res) => {
    try{
        const refreshToken = req.cookies["__Secure-rt"];
        
        if(!refreshToken){
            return res.status(401).json({ error: "No refresh token provided" });
        }
        const refresh_secret = process.env.JWT_REFRESH_SECRET;
        const decoded = jwt.verify(refreshToken, refresh_secret);

        if(!decoded){
            return res.status(403).json({ error: "Invalid refresh token" });
        }
        const payload = {
            id: decoded.id,
            name: decoded.name,
            email: decoded.email
        }
        const newAccessToken = generateAccessToken(payload);
        res.cookie("__Secure-at", newAccessToken, {
            maxAge: 15 * 60 * 1000,
            httpOnly: true,
            secure: false,
            sameSite: "strict"
        });
        return res.status(200).json({ message: "Access token refreshed" });
    }
    catch(error){
        return res.status(403).json({ error: "Invalid refresh token" });
    }
}

const ForgotPassword = async (req, res) => {
    try{
        const { email } = req.body;
        const userSchema = z.object({
            email: z.string().email("Invalid email address")
        })
        const validatedData = userSchema.parse({ email });
        const user = await User.findOne({
            where:{
                email: validatedData.email
            }   
        });
        if(!user){
            return res.status(404).json({ error: "Invalid email address" });
        }
        if(!user.is_verified){
            return res.status(403).json({ error: "Please verify email first" });
        }

        const password_resetToken = crypto.randomBytes(32).toString("hex");
        const password_resetExpires = new Date (Date.now() + 15 * 60 * 1000);
        const url = process.env.FRONTEND_BASE_URL;
        const resetPasswordUrl = `${url}/api/auth/forgot-password?token=${password_resetToken}&id=${user.id}`;
        
        const resetPassword = await PasswordResets.create({
            user_id: user.id,
            password_reset_token: password_resetToken,
            password_reset_expires: password_resetExpires,
        })
        await sendForgotPasswordEmail(validatedData.email, user.name, resetPasswordUrl);
        return res.status(200).json({message: "Password reset link sent successfully"});
    }
    catch(error){
        if(error instanceof ZodError){
            const formattedErrors =  error.issues.map((issue) => ({
                field: issue.path[0],
                message: issue.message
            }));
            return res.status(400).json({ errors: formattedErrors });
        }
        return res.status(500).json({error: "An error occurred in forgot password " + error });
    }
}

const VerifyPasswordToken = async (req, res) => {
    try{
        const { token, user_id } = req.query;
        if(!token){
            return res.status(400).json({error: "Token is required"});
        }
        if(!user_id){
            return res.status(400).json({error: "User id is required"});
        }
        const resetRecord = await PasswordResets.findOne({
            where: {
                password_reset_token: token,
                user_id: user_id
            }
        })
        if(!resetRecord){
            return res.status(400).json({error: "Invalid token or user"});
        }
        const tokenExists = await PasswordResets.findOne({
            where: {
                password_reset_token: token
            }
        });
        if(!tokenExists){
            return res.status(400).json({error: "Invalid Token"});
        }
        const userExists = await PasswordResets.findOne({
            where: {
                user_id: user_id
            }
        });
        if(!userExists){
            return res.status(400).json({error: "Invalid user id"})
        }

        if(tokenExists.password_reset_expires < new Date()){
            return res.status(400).json({error: "Token Expired"});
        }

        return res.status(200).json({message: "Token Verified Successfully"});
    }
    catch(error){
        return res.status(500).json({error: "An error occurred while verifying"});
    }
}

const NewPasswordForm = async (req, res) => {
    try{
        const { password } = req.body;
        const { token, user_id } = req.query;
        const userSchema = z.object({
        password: z.string().min(8, "Password must be atleast 8 characters")
    })
    const validatedData = userSchema.parse({ password });

    if(!token){
        return res.status(400).json({error: "Token is required"});
    }
    if(!user_id){
        return res.status(400).json({error: "User id is required"});
    }

    const resetRecord = await PasswordResets.findOne({
            where: {
                password_reset_token: token,
                user_id: user_id
            }
        })
    if(!resetRecord){
        return res.status(400).json({error: "Invalid token or user"});
    }

    if (resetRecord.password_reset_expires < new Date()) {
        return res.status(400).json({ error: "Token expired" });
    }

    const saltRounds = Number(process.env.SALT_ROUNDS);
    const hashedPassword = await bcrypt.hash(validatedData.password, saltRounds);
    const user = await User.update(
        { password: hashedPassword }, 
        { where: { id: user_id }}
    );

    await PasswordResets.update(
        { 
            password_reset_token: null,
            password_reset_expires: null
        },
        { where: { user_id } }
    );

    return res.status(200).json({message: "Password updated successfully"});
    }
    catch(error){
        if (error instanceof ZodError) {
            const formattedErrors = error.issues.map((issue) => ({
                field: issue.path[0],
                message: issue.message
            }));
            return res.status(400).json({ errors: formattedErrors });
        }
        return res.status(500).json({error: "An error occurred while updating password"});
    }
}


module.exports = { Signup, Login, VerifyEmail, RefreshToken, ForgotPassword, VerifyPasswordToken, NewPasswordForm };