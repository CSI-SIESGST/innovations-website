const mongoose = require('mongoose');

const broadcastSchema = new mongoose.Schema({

    time: Number,
    message: String,
    sender: {
        type: Boolean,
        default: true
    }
    
})

const Broadcast = new mongoose.model('Broadcast', broadcastSchema);

module.exports = Broadcast;