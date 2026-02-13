const express = require("express");
require('dotenv').config();
const { connectDB } = require("./config/db");

const User = require("./models/userModel");

const authRoute = require("./routes/authRoute");

const app = express();
const port = process.env.PORT;
app.use(express.json());

// DB Connection
connectDB();

// Model Sync
User.sync();

// API Routes
app.use("/api/auth", authRoute);


app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
