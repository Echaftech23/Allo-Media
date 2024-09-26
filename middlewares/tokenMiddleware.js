const validateToken = require("../validations/tokenValidation");
function checkTokenMiddleware(req, res, next) {
    console.log("checkTokenMiddleware");
    const token = req.params.token || req.cookies["authToken"];

    console.log("token is validdd");
    console.log(token);
    if (!token)
        return res
            .status(401)
            .json({ error: "Access denied, you need to log in" });
    // verify token
    const decoded_user = validateToken(token);
    if (!decoded_user.success) {
        return res.status(401).json({ error: "Access denied" });
    }
    console.log("token is valid");
    req.user = decoded_user.data;
    next();
}

module.exports = checkTokenMiddleware;