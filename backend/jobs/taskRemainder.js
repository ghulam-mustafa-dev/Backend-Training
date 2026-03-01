const cron = require("node-cron");
const TasksDueOnDate = require("../service/taskService");
const { SendTaskReminder } = require("../utils/emailVerification");

const startTaskReminderJob = () => {
    cron.schedule("0 0 * * *", async () => {

        const tasks = await TasksDueOnDate(new Date());

        for (const task of tasks) {
            await SendTaskReminder(
                task.User.email,
                task.User.name,
                task.title
            );
        }

    }, { timezone: "UTC" });
};

module.exports = startTaskReminderJob;