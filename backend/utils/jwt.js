const jwt = require("jsonwebtoken");


const access_secret = process.env.JWT_ACCESS_SECRET;
const refresh_secret = process.env.JWT_REFRESH_SECRET;

const generateAccessToken = (user) => {
    const accessToken = jwt.sign(user, access_secret, {
        expiresIn: '15m'
    });
    return accessToken;
}

const generateRefreshToken = (user) => {
    const refreshToken = jwt.sign(user, refresh_secret, {
        expiresIn: '90d'
    });
    return refreshToken;
}


module.exports = { generateAccessToken, generateRefreshToken };