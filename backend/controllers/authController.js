const User = require("../models/userModel");
const bcrypt = require("bcrypt");
const { z, ZodError } = require("zod");
const crypto = require("crypto");
const sendVerificationEmail = require("../utils/emailVerification");


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

        const existingEmail = await User.findOne({
            where: {
                email: validatedData.email
            }
        });
        if(existingEmail){
            return res.status(400).json({error: "User already exists with this email"});
        }

        const email_verificationToken = crypto.randomBytes(32).toString("hex");
        const email_verificationExpires = new Date(Date.now() + 60 * 60 * 1000);
        const url = process.env.BASE_URL;
        const emailVerificationUrl = `${url}/api/auth/verify-email?token=${email_verificationToken}`;

        const user = await User.create({
            name: validatedData.name,
            email: validatedData.email,
            password: hashedPassword,
            is_verified: false,
            email_verifcation_token: email_verificationToken,
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
        return res.status(500).json({error: "An error occured while registering user " + error});
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
        user.email_verifcation_token = null;
        user.email_verification_expires = null;
        await user.save();

        return res.status(200).json({message: "Email Verified Successfully"});
    }
    catch(error){
        return res.status(500).json({error: "An error occured while verifying email"});
    }
}

const Login = async (req, res) => {

}

module.exports = { Signup, Login, VerifyEmail };