const jwt = require("jsonwebtoken");


const access_secret = process.env.JWT_ACCESS_SECRET;

const authMiddleware = async (req, res, next) => {
    try{
        let accessToken = req.cookies["__Secure-at"];
        const decoded = jwt.verify(accessToken, access_secret);
        
        req.user = decoded
        next();
    }
    catch(error){
         if (error.name === "TokenExpiredError") {
            return res.status(401).json({ error: "Token expired" });
        }

        return res.status(403).json({ error: "Invalid token" });
    }
}

module.exports = authMiddleware;