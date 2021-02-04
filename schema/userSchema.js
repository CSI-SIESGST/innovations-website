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
	leaderName: {
		type: String,
		required: true
	},
	leaderCollege: {
		type: String,
		required: true
	},
	leaderContact: {
		type: String,
		required: true
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
	teamMembers: [
		{
			name: String,
			email: String,
			contact: String,
			college: String
		}
	],
	teamConfirm: {
		type: Boolean,
		required: true,
		default: false
	},
	mailTrack: {
		type: [Number],
		required: true,
		default: []
	},
	payment: {
		type: Boolean,
		required: true,
		default: false
	},
	submitted: {
		type: Boolean,
		required: true,
		default: false
	},
	status1: {
		type: Boolean,
		required: true,
		default: false
	},
	status2: {
		type: Number,
		required: true,
		default: 0
	},
	graded1: {
		type: Boolean,
		required: true,
		default: false
	},
	graded2: {
		type: Boolean,
		required: true,
		default: false
	},
	uploadLink: {
		type: String,
		required: true,
		default: ' '
	}
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User', userSchema);

module.exports = User;
