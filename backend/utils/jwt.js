const jwt = require("jsonwebtoken");


const secret_key = process.env.JWT_SECRET_KEY;

const generateAccessToken = (user) => {
    const accessToken = jwt.sign(user, secret_key, {
        expiresIn: '15m'
    });
    return accessToken;
}

const generateRefreshToken = (user) => {
    const refreshToken = jwt.sign(user, secret_key, {
        expiresIn: '90d'
    });
    return refreshToken;
}


module.exports = { generateAccessToken, generateRefreshToken };