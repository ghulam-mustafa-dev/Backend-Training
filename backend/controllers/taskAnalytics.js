const Task = require("../models/TaskModel");
const User = require("../models/userModel");
const { fn, col } = require("sequelize");


const TaskSummary = async (req, res) => {
    try{
        const totalTasks = await Task.count({
            where: {
                user_id: req.user.id
            }
        });
        const completedTasks = await Task.count({
            where: {
                user_id: req.user.id,
                completion_status: true
            }
        });
        const remainingTasks = await Task.count({
            where: {
                user_id: req.user.id,
                completion_status: false
            }
        });
        return res.status(200).json({"Total Tasks" : totalTasks, "Completed Tasks" : completedTasks, "Remaining Tasks" : remainingTasks});
    }
    catch(error){
        return res.status(500).json({error: "An error occurred"});
    }
}

const AverageTasksPerDay = async (req, res) => { 
    try{
        const totalCompletedTasks = await Task.count({
            where: {
                user_id: req.user.id,
                completion_status: true
            }
        });
        const now = new Date();
        const user = await User.findOne({
            where: {
                id: req.user.id
            }
        });
        const user_createdAt = new Date(user.createdAt);
        const daySinceCreation = Math.max(
            1, Math.ceil((now - user_createdAt) / (1000 * 60 * 60 * 24))
        );

        const averagePerDay = totalCompletedTasks / daySinceCreation;

        return res.status(200).json({"Average Tasks Completed Per Day Since Account Creation" : averagePerDay });
    }
    catch(error){
        return res.status(500).json({error: "An error occurred"});
    }
}

const OverdueTaskCount = async (req, res) => { 
    try{
        const taskCount = await Task.findAll({
            where: {
                user_id: req.user.id,
                completion_status: true,
            }
        });
        const overdueTasks = taskCount.filter(task => {
            task.completion_date_time > task.due_date_time
        });
        const overdueCount = overdueTasks.length;
        return res.status(200).json({"Count of Tasks not completed on time": overdueCount});
    }
    catch(error){
        return res.status(500).json({error: "An error occurred"});
    }
}

const MaxTasksCompletedDate = async (req, res) => { 
    try{
        const tasks = await Task.findAll({
            where: {
                user_id: req.user.id,
                completion_status: true,
            },
            attributes: [
                [fn("COUNT", col("id")), "task_count"],
            ],
            group: [fn("DATE", col("completion_date_time"))],
            order: [[fn("COUNT", col("id")), "DESC"]],
        });
        return res.status(200).json({"Max Count": tasks[0]});
    }
    catch(error){
        return res.status(500).json({error: "An error occurred"});
    }
}

const TasksByWeekday = async (req, res) => { 
    try{
        const tasks = await Task.findAll({
            where: {
                user_id: req.user.id,
            },
        });
        const weekdayCounts = {
            Sunday: 0,
            Monday: 0,
            Tuesday: 0,
            Wednesday: 0,
            Thursday: 0,
            Friday: 0,
            Saturday: 0
            };

            tasks.forEach(task => {
            const date = new Date(task.createdAt);
            const dayName = date.toLocaleString("en-US", { weekday: "long" });
            weekdayCounts[dayName]++;
            });
        return res.status(200).json({"Weekly Distribution of Tasks": weekdayCounts});
    }
    catch(error){
        return res.status(500).json({error: "An error occurred" + error});
    }
}

module.exports = { TaskSummary, AverageTasksPerDay, OverdueTaskCount, MaxTasksCompletedDate, TasksByWeekday };

