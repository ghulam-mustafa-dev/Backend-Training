const { Sequelize } = require('sequelize');
require('dotenv').config();


const host = process.env.DB_HOST;
const db = process.env.DB_NAME;
const user = process.env.DB_USER;
const password = process.env.DB_PASSWORD;


const sequelize = new Sequelize(db, user, password, {
  host: host,
  dialect: 'postgres'
});

const connectDB = async () => {
    try {
        await sequelize.authenticate();
        console.log('DB Connection has been established successfully.');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
}


module.exports = { connectDB, sequelize };