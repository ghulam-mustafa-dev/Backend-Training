const express = require("express");
const { CreateTask } = require("../controllers/taskController");
const router = express.Router();

router.post("/", CreateTask);


module.exports = router;