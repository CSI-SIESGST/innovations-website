const axios = require('axios');
const qs = require('qs');

const User = require('../schema/userSchema');

const resetPassword = (data) => {
	// eslint-disable-next-line no-unused-vars
	return new Promise(function (resolve, reject) {
		User.where({ username: data.email }).findOne((err, user) => {
			if (err) {
				console.log(0, JSON.stringify(err));
				resolve(0);
				return;
			} else if (user) {
				if (
					user.mailTrack.length == 5 &&
					user.mailTrack[0] + 24 * 60 * 60 * 1000 >
						new Date().getTime()
				) {
					resolve(3);
					return;
				}
				// eslint-disable-next-line no-undef
				axios
					.post(process.env.RESET_URL, qs.stringify(data))
					.then((response) => {
						if (response.data.status === 1) {
							if (user.mailTrack.length === 5) {
								user.mailTrack.shift();
							}
							user.mailTrack.push(new Date().getTime());

							user.resetPw = {
								time: new Date().getTime(),
								code: data.code,
								available: true
							};

							user.save();

							resolve(1);
							return;
						} else {
							console.log(
								4,
								'Mail send error',
								JSON.stringify(response)
							);
							resolve(4);
							return;
						}
					})
					.catch((error) => {
						console.log(5, JSON.stringify(error));
						resolve(5);
						return;
					});
			} else {
				resolve(2);
				return;
			}
		});
	});
};

module.exports = resetPassword;