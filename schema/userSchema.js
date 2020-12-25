const mongoose = require('mongoose');
const validator = require('validator');
const passportLocalMongoose = require('passport-local-mongoose');
const findOrCreate = require('mongoose-findorcreate');

const userSchema = new mongoose.Schema({
	username: {
        type: String,
        required: [true, 'Email Address Required'],
        trim: true,
        lowercase: [true, 'Invalid Email Address'],
        unique: [true, 'You have already Registered!'],
        validate: {
            validator: (value) => {
                return validator.isEmail(value);
            },
            message: 'Invalid email address provided'
        }
    },
	password: {
        type: String
    },
    teamName: {
        type: String,
        required: [true, 'Team Name Required'],
        unique: [true, 'Team Name already taken!'],
        minLength: 4
    },
    verified: {
        type: Boolean,
        required: true
    },
    mailTrack: {
        type: [Number],
        required: true,
        default: []
    }
    
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User', userSchema);

module.exports = User;