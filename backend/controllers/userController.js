const User = require("../models/userModel");
const bcrypt = require("bcrypt");
const { z, ZodError } = require("zod");


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
            return res.status(400).json({error: "Email already taken"});
        }
        const user = await User.create({
            name: validatedData.name,
            email: validatedData.email,
            password: hashedPassword
        });
        
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

const Login = async (req, res) => {

}

module.exports = { Signup, Login };