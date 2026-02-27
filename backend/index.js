const express = require("express");
require('dotenv').config();
const { connectDB } = require("./config/db");
const cookieParser = require("cookie-parser");
const User = require("./models/userModel");
const PasswordReset = require("./models/PasswordResetModel");
const Task = require("./models/TaskModel");
require("./models/index");
const authRoute = require("./routes/authRoute");
const taskRoute = require("./routes/taskRoute");
const taskAnalyticsRoute = require("./routes/taskAnalyticsRoute");

const app = express();
const port = process.env.PORT;
app.use(express.json());
app.use(cookieParser());

// DB Connection
connectDB();

// Model Sync
User.sync();
PasswordReset.sync();
Task.sync();

// API Routes
app.use("/api/auth", authRoute);
app.use("/api/task", taskRoute);
app.use("/api/task/analytics", taskAnalyticsRoute);


app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
