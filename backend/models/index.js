const PasswordReset = require("./PasswordResetModel");
const User = require("./userModel");
const Task = require("./TaskModel");

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


module.exports = { User, PasswordReset, Task };