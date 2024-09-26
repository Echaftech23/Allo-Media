const Joi = require('joi');

// Register Validation
function validateRegister(body){
    const registerSchema = Joi.object({
        name: Joi.string().min(6).required(),
        email: Joi.string().min(6).required().email(),
        password: Joi.string().min(6).required(),
        role: Joi.string().required(),
    });
    return registerSchema.validate(body);
}

function validateLogin(body){
    const loginSchema = Joi.object({
        email: Joi.string().min(6).required().email(),
        password: Joi.string().min(6).required(),
    });
    return loginSchema.validate(body);
}


module.exports.validateForms ={
    validateRegister,
    validateLogin
};