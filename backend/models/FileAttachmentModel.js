const { DataTypes } = require('sequelize');
const { sequelize } = require("../config/db");

const FileAttachment = sequelize.define(
  'FileAttachment',
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
    task_id: {
        type: DataTypes.UUID,
        references: {
            model: 'tasks',
            key: 'id'
        },
        allowNull: false,
    },
    file_name: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        notEmpty: true,
      }
    },
    file_path: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
            notEmpty: true
        }
    },
    file_type: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
            notEmpty: true
        }
    },
    file_size:{
        type: DataTypes.INTEGER,
        allowNull: false,
    }
  },
  {
    // Other model options go here  
    timestamps: true,
    tableName: 'file_attachments'
  },
);

module.exports = FileAttachment;