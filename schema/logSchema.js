const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
	time: Number,
	trigger: Boolean,
	event: String
});

const Log = new mongoose.model('Log', logSchema);

module.exports = Log;
