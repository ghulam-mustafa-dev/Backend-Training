const express = require("express");
require('dotenv').config();
const { connectDB } = require("./config/db");
const cookieParser = require("cookie-parser");
const User = require("./models/userModel");
const PasswordResets = require("./models/PasswordResetModel");
require("./models/index");
const authRoute = require("./routes/authRoute");

const app = express();
const port = process.env.PORT;
app.use(express.json());
app.use(cookieParser());

// DB Connection
connectDB();

// Model Sync
User.sync();
PasswordResets.sync();

// API Routes
app.use("/api/auth", authRoute);


app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
