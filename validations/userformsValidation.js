const Joi = require('joi');

// Register Validation
function validateRegister(body){
    const registerSchema = Joi.object({
        name: Joi.string().min(6).required(),
        email: Joi.string().min(6).required().email(),
        password: Joi
        .string()
        .pattern(new RegExp('^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$'))
        .required()
        .messages({
            'string.pattern.base': 'Password must be at least 8 characters long, include one uppercase letter, one lowercase letter, and one number',
        }),
        phone: Joi
            .string()
            .pattern(new RegExp('^\\+\\d{1,3}\\d{4,14}$'))
            .required()
            .messages({
            'string.pattern.base': 'Phone number must be in international format',
        }),
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

function validateEmail(body){
    const emailSchema = Joi.object({
        email: Joi.string().min(6).required().email(),
    });
    return emailSchema.validate(body);
}

// validate password with confirm password
function validatePassword(body){
    const passwordSchema = Joi.object({
        // password should match confirm password
        password: Joi.string().min(6).required().valid(Joi.ref('confirmPassword')).messages({
            'any.only': 'password does not match'
        }),
        confirmPassword: Joi.string().min(6).required(),

    });
    return passwordSchema.validate(body);
}

module.exports.validateForms ={
    validateRegister,
    validateLogin,
    validateEmail,
    validatePassword
};