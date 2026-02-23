const { DataTypes } = require('sequelize');
const { sequelize } = require("../config/db");


const PasswordReset = sequelize.define(
  'PasswordReset',
  {
    // Model attributes are defined here
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false,
        primaryKey: true,
        validate: {
            notEmpty: true
        }
    },
    user_id: {
        type: DataTypes.UUID,
        references: {
          model: 'users',
          key: 'id'
        },
        allowNull: false,
        unique: true,
        validate: {
            notEmpty: true
        }
    },
    password_reset_token: {
      type: DataTypes.STRING,
    },
    password_reset_expires: {
      type: DataTypes.DATE,
    }
  },
  {
    // Other model options go here
    timestamps: true,
    tableName: 'password_resets'
  },
);


module.exports = PasswordReset;