const express = require("express");
const router = express.Router();
const authMiddleware = require("../middleware/authMiddleware");
const { TaskSummary, TasksByWeekday, MaxTasksCompletedDate, OverdueTaskCount, AverageTasksPerDay } = require("../controllers/taskAnalytics");

router.get("/task-summary", authMiddleware, TaskSummary);
router.get("/avg-per-day", authMiddleware, AverageTasksPerDay);
router.get("/overdue-count", authMiddleware, OverdueTaskCount);
router.get("/max-completed-date", authMiddleware, MaxTasksCompletedDate);
router.get("/weekly-distribution", authMiddleware, TasksByWeekday);


module.exports = router;