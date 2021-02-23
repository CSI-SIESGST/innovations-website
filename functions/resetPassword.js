const axios = require('axios');
const qs = require('qs');

const User = require('../schema/userSchema');

const resetPassword = (data) => {
	// eslint-disable-next-line no-unused-vars
	return new Promise(function (resolve, reject) {
		let send = true;

		User.where({ username: data.email }).findOne((err, user) => {
			if (err) {
				console.log(0, JSON.stringify(err));
				resolve(0);
				send = false;
			} else if (user) {
				if (
					user.mailTrack.length == 5 &&
					user.mailTrack[0] + 24 * 60 * 60 * 1000 >
						new Date().getTime()
				) {
					resolve(3);
					send = false;
				}
				// eslint-disable-next-line no-undef
				if (send) {
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
								send = false;
							} else {
								console.log(4, 'Mail send error', response);
								resolve(4);
								send = false;
							}
						})
						.catch((error) => {
							console.log(5, JSON.stringify(error));
							resolve(5);
							send = false;
						});
				}
			} else {
				resolve(2);
				send = false;
			}
		});
	});
};

module.exports = resetPassword;
