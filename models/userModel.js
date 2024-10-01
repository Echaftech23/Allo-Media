const Role = require('./RoleModel');
const mongoose = require('mongoose');

const schema = {
    name: {
        type: String,
        required: true,
        min: 6,
        max: 255,
    },
    email: {
        type: String,
        required: true,
        min: 6,
        max: 255,
    },
    password: {
        type: String,
        required: true,
    },
    is_verified: {
        type: Boolean,
        default: false
    },
    lastLogin: {
        type: Date,
        default: null,
    },
    date: {
        type: Date,
        required: true,
        default: Date.now,
    },
    role: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Role',
        required: true,
        validate: {
            validator: async function (roleId) {
                const role = await Role.findById(roleId);
                return role != null;
            },
            message: 'Role does not exist sadly',
        },
    }
}

const userSchema = new mongoose.Schema(schema);

module.exports = mongoose.model('User', userSchema);