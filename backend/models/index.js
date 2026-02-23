const PasswordReset = require("./PasswordResetModel");
const User = require("./userModel");
const Task = require("./TaskModel");
const FileAttachment = require("./FileAttachmentModel");

// user - password reset
User.hasMany(PasswordReset, {
  foreignKey: 'user_id',
})

PasswordReset.belongsTo(User, {
  foreignKey: 'user_id',
});

// user - task
User.hasMany(Task, {
  foreignKey: 'user_id'
});

Task.belongsTo(User, {
  foreignKey: 'user_id'
});

// task - file attachment
Task.hasMany(FileAttachment, {
  foreignKey: 'task_id'
});

FileAttachment.belongsTo(Task, {
  foreignKey: 'task_id'
});

module.exports = { User, PasswordReset, Task, FileAttachment };