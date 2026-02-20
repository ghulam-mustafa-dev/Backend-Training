const PasswordResets = require("./PasswordResetModel");
const User = require("./userModel");


User.hasMany(PasswordResets, {
  foreignKey: 'user_id',
})

PasswordResets.belongsTo(User, {
  foreignKey: 'user_id',
});

module.exports = { User, PasswordResets };