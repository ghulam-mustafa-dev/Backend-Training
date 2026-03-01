const { Op } = require("sequelize");
const Task = require("../models/TaskModel");
const User = require("../models/userModel");

const TasksDueOnDate = async (date) => {
    const start = new Date(date);
    start.setUTCHours(0, 0, 0, 0);

    const end = new Date(start);
    
    end.setUTCDate(start.getUTCDate() + 1);

    return Task.findAll({
        where: {
            due_date_time: {
                [Op.gte]: start,
                [Op.lt]: end
            }
        },
        include: [{ model: User }]
    });
};

module.exports = TasksDueOnDate;