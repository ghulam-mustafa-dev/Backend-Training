const { DataTypes } = require('sequelize');
const { sequelize } = require("../config/db");

const Task = sequelize.define(
  'tasks',
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
    },
    title: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        notEmpty: true,
      }
    },
    description: {
        type: DataTypes.TEXT,
        allowNull: true,
    },
    due_date_time:{
        type: DataTypes.DATE,
        allowNull: false,
    },
    completion_status: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
    },
    completion_date_time:{
        type: DataTypes.DATE,
        allowNull: true
    }
  },
  {
    // Other model options go here  
    timestamps: true,
    tableName: 'tasks'
  },
);

module.exports = Task;