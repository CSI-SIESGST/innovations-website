const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
	time: Number,
	message: String,
	sender: {
		type: Boolean,
		default: true
	}
});

const Log = new mongoose.model('Broadcast', logSchema);

module.exports = Log;
