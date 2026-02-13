const { DataTypes, ValidationError } = require('sequelize');
const { sequelize } = require("../config/db");
const { application } = require('express');

const User = sequelize.define(
  'user',
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
    name: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        notEmpty: true,
        len: [3, 40]
      }
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        isEmail: true,
        notEmpty: true
      }
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        notEmpty: true,
        len: [8, 60]
      }
    },
  },
  {
    // Other model options go here
    timestamps: true
  },
);

module.exports = User;


// validate: {
//   notEmpty: true    Means that the value cannot be sent as empty quotes like ""
// }

// Sending "null" also gets stored because its a string
// name: 123 also gets stored as string
// Send null value gives 'cannot be null' error


//  "password": 1111111111
// This gives 'data must be a string or Buffer' error and crash the application, thats why we do backend validation so application dosent crash

// DB vs Backend Validation difference
// Database validation is validation of how data will be stored
// Backend validation is validation of which data (of which type, format) will be stored

// len: [8, 50] gives error because bcrypt hashed password is 60 characters, so it dosent gets stored and gives 'Validation len on password failed' error.