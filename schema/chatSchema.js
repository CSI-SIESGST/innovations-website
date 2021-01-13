const mongoose = require('mongoose');

const chatSchema = new mongoose.Schema({
	teamName: {
		type: String,
		unique: true,
		required: true
	},
	messages: [
		{
			time: Number,
			message: String,
			sender: Boolean
		}
	],
	adminUnread: {
		type: Boolean,
		default: false
	},
	userUnread: {
		type: Boolean,
		default: false
	}
});

const Chat = new mongoose.model('Chat', chatSchema);

module.exports = Chat;
