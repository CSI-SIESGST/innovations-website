require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
require('ejs');
const session = require('express-session');
const passport = require('passport');
const CryptoJS = require('crypto-js');
const rateLimit = require('express-rate-limit');
const anchorme = require('anchorme').default;

const admin = require('firebase-admin');
const formidable = require('formidable');

const verifyEmail = require('./functions/verifyEmail');
const resetPassword = require('./functions/resetPassword');

require('./db/mongoose');

const User = require('./schema/userSchema');
const Chat = require('./schema/chatSchema');
const Broadcast = require('./schema/broadcastSchema');
const Log = require('./schema/logSchema');
const { domain } = require('process');

const indCost = 500;

const regEndDate =
	new Date('Jan 23, 2022 23:59:59').getTime() +
	(330 + new Date().getTimezoneOffset()) * 60000;

const teamConfirmDate = '23/02/2022';

const teamConfirmDeadline =
	new Date('Jan 23, 2022 23:59:59').getTime() +
	(330 + new Date().getTimezoneOffset()) * 60000;

const submissionDate = '23/02/2022';

const submissionDeadline =
	new Date('Jan 23, 2022 23:59:59').getTime() +
	(330 + new Date().getTimezoneOffset()) * 60000;

const round1Date = `<span class="d-inline-block">00/00/00 at</span> <span class="d-inline-block">00:00 PM IST</span>`;

const round1Result =
	new Date('Jan 23, 2021 23:59:59').getTime() +
	(330 + new Date().getTimezoneOffset()) * 60000;

const paymentDate = '23/02/2022';

const paymentDeadline =
	new Date('Jan 23, 2022 23:59:59').getTime() +
	(330 + new Date().getTimezoneOffset()) * 60000;

const round2DateTime = `<span class="d-inline-block">00/00/00 at</span> <span class="d-inline-block">00:00 PM IST</span>`;

const round2Link = '#';

const round2Start =
	new Date('Jan 23, 2021 23:59:59').getTime() +
	(330 + new Date().getTimezoneOffset()) * 60000;

const round2ResultTime = `<span class="d-inline-block">00/00/00 at</span> <span class="d-inline-block">00:00 PM IST</span>`;

const round2End =
	new Date('Jan 23, 2021 23:59:59').getTime() +
	(330 + new Date().getTimezoneOffset()) * 60000;

const round2Result =
	new Date('Jan 23, 2021 23:59:59').getTime() +
	(330 + new Date().getTimezoneOffset()) * 60000;

const serviceAccount = {
	type: 'service_account',
	project_id: process.env.PROJECT_ID,
	private_key_id: process.env.PRIVATE_KEY_ID,
	private_key: process.env.PRIVATE_KEY.replace(/\\n/g, '\n'),
	client_email: process.env.CLIENT_EMAIL,
	client_id: process.env.CLIENT_ID,
	auth_uri: 'https://accounts.google.com/o/oauth2/auth',
	token_uri: 'https://oauth2.googleapis.com/token',
	auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
	client_x509_cert_url: process.env.CERT_URL
};

//initialize firebase app
admin.initializeApp({
	credential: admin.credential.cert(serviceAccount),
	storageBucket: 'csi-innovations.appspot.com'
});

//firebase bucket
var bucket = admin.storage().bucket();

//function to upload file
async function uploadFile(filepath, filename) {
	await bucket.upload(filepath, {
		gzip: true,
		destination: filename,
		metadata: {
			cacheControl: 'public, max-age=31536000'
		}
	});

	console.log(`${filename} uploaded to bucket.`);
}

async function generateSignedUrl(filename) {
	const options = {
		version: 'v2',
		action: 'read',
		expires: Date.now() + 1000 * 60 * 60
	};

	const [url] = await bucket.file(filename).getSignedUrl(options);
	return url;
}

const app = express();

const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 500 // limit each IP to 500 requests per windowMs
});

const createAccountLimiter = rateLimit({
	windowMs: 60 * 60 * 1000, // 1 hour window
	max: 5, // start blocking after 5 requests
	message:
		'Too many accounts created from this IP, please try again after an hour'
});

app.set('trust proxy', '127.0.0.1');
app.use(limiter);

app.set('view engine', 'ejs');

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(
	session({
		// eslint-disable-next-line no-undef
		secret: process.env.SECRET_KEY,
		resave: false,
		saveUninitialized: false
	})
);

app.use(passport.initialize());
app.use(passport.session());

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
	done(null, user.id);
});

passport.deserializeUser(function (id, done) {
	User.findById(id, function (err, user) {
		done(err, user);
	});
});

const server = require('http').Server(app);
const io = require('socket.io')(server);

io.on('connection', (socket) => {
	// eslint-disable-next-line no-undef
	socket.on(process.env.ADMIN_EVENT, () => {
		// eslint-disable-next-line no-undef
		socket.join(process.env.ADMIN_ROOM);
	});

	socket.on('join-room', (chatsId) => {
		socket.join(chatsId);
	});

	socket.on('user-read', (chatsId, teamName) => {
		Chat.findById(chatsId, (err, chat) => {
			if (err) {
				// eslint-disable-next-line no-undef
				socket.to(chatsId).emit('refresh');
			} else {
				if (chat.userUnread) {
					chat.userUnread = false;
					chat.save();
				}
			}
		});

		// eslint-disable-next-line no-undef
		socket.to(process.env.ADMIN_ROOM).emit('user-read', teamName);
		socket.to(chatsId).emit('chat-scroll');
	});

	socket.on('admin-read', (chatsId) => {
		Chat.findById(chatsId, (err, chat) => {
			if (err) {
				// eslint-disable-next-line no-undef
				socket.to(process.env.ADMIN_ROOM).emit('refresh');
			} else {
				if (chat.adminUnread) {
					chat.adminUnread = false;
					chat.save();
				}
			}
		});

		socket.to(chatsId).emit('admin-read');
	});

	socket.on('msg-to-admin', (teamName, message, chatsId, callback) => {
		message = message.trim();
		if (message.length > 0) {
			Chat.where({ teamName: teamName }).findOne((err, chat) => {
				if (err) {
					// eslint-disable-next-line no-undef
					socket.to(chatsId).emit('refresh');
				} else {
					var time = new Date().getTime();

					callback({ time: time });

					let fmsg = String(message)
						.replace(/&/g, '&amp;')
						.replace(/</g, '&lt;')
						.replace(/>/g, '&gt;')
						.replace(/"/g, '&quot;')
						.replace(/(\r\n|\n)/g, '<br/>');

					// eslint-disable-next-line no-undef
					socket
						.to(process.env.ADMIN_ROOM)
						.emit('new-msg', teamName, fmsg, time);

					chat.messages.push({
						time: time,
						message: fmsg,
						sender: false
					});
					chat.adminUnread = true;

					chat.save();
				}
			});
		}
	});

	socket.on('msg-to-user', (teamName, message, chatsId, callback) => {
		Chat.where({ teamName: teamName }).findOne((err, chat) => {
			if (err) {
				// eslint-disable-next-line no-undef
				socket.to(process.env.ADMIN_ROOM).emit('refresh');
			} else {
				var time = new Date().getTime();

				message = anchorme({
					input: message,
					options: {
						attributes: { target: '_blank', class: 'msg-link' },
						truncate: function (string) {
							if (
								string.startsWith(
									'https://teams.microsoft.com/'
								) > -1
							) {
								return 40;
							} else {
								return 10;
							}
						},
						middleTruncation: false,
						specialTransform: [
							{
								test: /^https:\/\/teams.microsoft.com/,
								transform: (string) =>
									`<a target="_blank" class="msg-link" href="${string}">Microsoft Teams Meeting</a>`
							}
						]
					}
				});

				callback({ time: time });
				socket.to(chatsId).emit('new-msg', teamName, message, time);

				chat.messages.push({
					time: time,
					message: message,
					sender: true
				});
				chat.userUnread = true;

				chat.save();
			}
		});
	});

	// eslint-disable-next-line no-undef
	socket.on(process.env.ADMIN_BROADCAST, (message, mode, callback) => {
		message = anchorme({
			input: message,
			options: {
				attributes: { target: '_blank', class: 'msg-link' },
				truncate: function (string) {
					if (
						string.startsWith('https://teams.microsoft.com/') > -1
					) {
						return 40;
					} else {
						return 10;
					}
				},
				middleTruncation: false,
				specialTransform: [
					{
						test: /^https:\/\/teams.microsoft.com/,
						transform: (string) =>
							`<a target="_blank" class="msg-link" href="${string}">Microsoft Teams Meeting</a>`
					}
				]
			}
		});

		let ogMsg = message;

		message = '<small><b>Broadcast Message</b></small><br>' + message;

		var time = new Date().getTime();

		if (mode == 1 || mode == 5) {
			Chat.updateMany(
				{},
				{
					$push: {
						messages: { time: time, message: message, sender: true }
					}
				},
				(err) => {
					if (err) {
						console.log(err);
					} else {
						Chat.updateMany({}, { userUnread: true }, (error) => {
							if (error) {
								console.log(error);
							}
						});
					}
				}
			);

			var broadcast = new Broadcast({ time: time, message: message });
			broadcast.save();

			callback();

			socket.broadcast.emit('new-msg', '', message, time);

			if (mode == 5) {
				let uNameList = [];
				User.where({}).find((err, users) => {
					if (err) {
						console.log(err);
					} else {
						users.forEach((user) => {
							uNameList.push(user.username);
						});
						emailTo(uNameList, ogMsg);
					}
				});
			}
		} else if (mode == 2 || mode == 6) {
			User.where({ status1: true }).find((err, users) => {
				if (err) {
					console.log(err);
				} else {
					let idList = [];
					let uNameList = [];
					users.forEach((user) => {
						idList.push(user.teamName);
						uNameList.push(user.username);
					});

					Chat.updateMany(
						{ teamName: { $in: idList } },
						{
							$push: {
								messages: {
									time: time,
									message: message,
									sender: true
								}
							}
						},
						(err) => {
							if (err) {
								console.log(err);
							} else {
								Chat.updateMany(
									{ teamName: { $in: idList } },
									{ userUnread: true },
									(error) => {
										if (error) {
											console.log(error);
										} else {
											callback();

											Chat.where({
												teamName: { $in: idList }
											}).find((errors, chats) => {
												if (errors) {
													console.log(errors);
												} else {
													chats.forEach((chat) => {
														socket
															.to(
																chat._id.toString()
															)
															.emit(
																'new-msg',
																'',
																message,
																time
															);
													});

													if (mode == 6) {
														emailTo(
															uNameList,
															ogMsg
														);
													}
												}
											});
										}
									}
								);
							}
						}
					);
				}
			});
		} else if (mode == 3 || mode == 7) {
			User.where({ status1: true, payment: false }).find((err, users) => {
				if (err) {
					console.log(err);
				} else {
					let idList = [];
					let uNameList = [];
					users.forEach((user) => {
						idList.push(user.teamName);
						uNameList.push(user.username);
					});

					Chat.updateMany(
						{ teamName: { $in: idList } },
						{
							$push: {
								messages: {
									time: time,
									message: message,
									sender: true
								}
							}
						},
						(err) => {
							if (err) {
								console.log(err);
							} else {
								Chat.updateMany(
									{ teamName: { $in: idList } },
									{ userUnread: true },
									(error) => {
										if (error) {
											console.log(error);
										} else {
											callback();

											Chat.where({
												teamName: { $in: idList }
											}).find((errors, chats) => {
												if (errors) {
													console.log(errors);
												} else {
													chats.forEach((chat) => {
														socket
															.to(
																chat._id.toString()
															)
															.emit(
																'new-msg',
																'',
																message,
																time
															);
													});

													if (mode == 7) {
														emailTo(
															uNameList,
															ogMsg
														);
													}
												}
											});
										}
									}
								);
							}
						}
					);
				}
			});
		} else if (mode == 4 || mode == 8) {
			User.where({ status1: true, payment: true }).find((err, users) => {
				if (err) {
					console.log(err);
				} else {
					let idList = [];
					let uNameList = [];
					users.forEach((user) => {
						idList.push(user.teamName);
						uNameList.push(user.username);
					});

					Chat.updateMany(
						{ teamName: { $in: idList } },
						{
							$push: {
								messages: {
									time: time,
									message: message,
									sender: true
								}
							}
						},
						(err) => {
							if (err) {
								console.log(err);
							} else {
								Chat.updateMany(
									{ teamName: { $in: idList } },
									{ userUnread: true },
									(error) => {
										if (error) {
											console.log(error);
										} else {
											callback();

											Chat.where({
												teamName: { $in: idList }
											}).find((errors, chats) => {
												if (errors) {
													console.log(errors);
												} else {
													chats.forEach((chat) => {
														socket
															.to(
																chat._id.toString()
															)
															.emit(
																'new-msg',
																'',
																message,
																time
															);
													});

													if (mode == 8) {
														emailTo(
															uNameList,
															ogMsg
														);
													}
												}
											});
										}
									}
								);
							}
						}
					);
				}
			});
		}
	});
});

app.get('/', (req, res) => {
	if (req.isAuthenticated()) {
		res.render('newindex', { team: req.user.teamName });
	} else {
		res.render('newindex', { team: null });
	}
});

app.get('/members', (req, res) => {
	if (req.isAuthenticated()) {
		if (
			!req.user.verified ||
			!(
				req.user.teamConfirm ||
				new Date().getTime() < teamConfirmDeadline
			)
		) {
			res.redirect('/home');
		} else {
			res.render('members', {
				leaderName: req.user.leaderName,
				username: req.user.username,
				leaderCollege: req.user.leaderCollege,
				leaderContact: req.user.leaderContact,
				teamConfirm: req.user.teamConfirm,
				teamMembers: req.user.teamMembers
			});
		}
	} else {
		res.redirect('/login');
	}
});

app.post('/abstract', (req, res) => {
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		let log = new Log({
			time: new Date().getTime(),
			trigger: true,
			event:
				req.session[process.env.ADMIN_NAME] +
				' (Admin) viewed abstract named <b>' +
				req.body.filename +
				'</b>'
		});

		log.save();

		generateSignedUrl(req.body.filename).then((url) => {
			res.status(200).json({ url });
		});
	} else {
		res.redirect('/csi-admin-login');
	}
	//res.status(200).json({url: url});
});

app.post('/members', (req, res) => {
	if (req.isAuthenticated()) {
		if (!req.user.verified) {
			res.status(401);
		} else if (
			req.user.teamConfirm ||
			new Date().getTime() > teamConfirmDeadline
		) {
			res.status(401);
		} else {
			const num = parseInt(req.body.num);

			for (let i = 2; i <= num; i++) {
				req.user.teamMembers.push({
					name: String(req.body['name' + i])
						.replace(/&/g, '&amp;')
						.replace(/</g, '&lt;')
						.replace(/>/g, '&gt;')
						.replace(/"/g, '&quot;'),
					email: String(req.body['email' + i])
						.replace(/&/g, '&amp;')
						.replace(/</g, '&lt;')
						.replace(/>/g, '&gt;')
						.replace(/"/g, '&quot;'),
					contact: String(req.body['contact' + i])
						.replace(/&/g, '&amp;')
						.replace(/</g, '&lt;')
						.replace(/>/g, '&gt;')
						.replace(/"/g, '&quot;'),
					college: String(req.body['college' + i])
						.replace(/&/g, '&amp;')
						.replace(/</g, '&lt;')
						.replace(/>/g, '&gt;')
						.replace(/"/g, '&quot;')
				});
			}

			let log = new Log({
				time: new Date().getTime(),
				trigger: false,
				event: '<b>' + req.user.teamName + '</b> confirmed their team!'
			});
			log.save();

			req.user.teamConfirm = true;
			req.user.save();
			res.send({ message: 'done' });
		}
	} else {
		res.status(401);
	}
});

app.get('/payment', (req, res) => {
	if (req.isAuthenticated()) {
		if (!req.user.verified) {
			res.redirect('/home');
		} else {
			res.render('payment', {
				payment: req.user.payment
			});
		}
	} else {
		res.redirect('/login');
	}
});

app.get('/final-results', (req, res) => {
	if (
		req.isAuthenticated() &&
		req.user.verified &&
		new Date().getTime() > round2Result
	) {
		User.find({ graded2: true, domain: req.user.domain })
			.sort({ status2: -1 })
			.limit(5)
			.exec((err, users) => {
				if (err) {
					res.status(500).send('There was an error!');
				} else if (users) {
					res.render('round2Results', { users: users });
				} else {
					res.status(500).send('There was an error!');
				}
			});
	} else {
		res.redirect('/home');
	}
});

app.get('/upload', (req, res) => {
	if (req.isAuthenticated()) {
		if (
			!req.user.verified ||
			!req.user.teamConfirm ||
			(!req.user.submitted && new Date().getTime() > submissionDeadline)
		) {
			res.redirect('/home');
		} else {
			res.render('abstract', {
				teamConfirm: req.user.teamConfirm,
				payment: req.user.payment,
				submitted: req.user.submitted
			});
		}
	} else {
		res.redirect('/login');
	}
});

app.post('/upload', (req, res) => {
	console.log(req.user.teamConfirm);
	if (req.isAuthenticated()) {
		if (
			!req.user.verified ||
			!req.user.teamConfirm ||
			req.user.submitted ||
			new Date().getTime() > submissionDeadline
		) {
			res.status(401).end();
		} else {
			var form = new formidable.IncomingForm();
			form.parse(req, function (err, fields, files) {
				if (files.file) {
					if (files.file.type != 'application/pdf') {
						res.status(400).json({
							message: 'File must be of type PDF'
						});
					} else if (files.file.size > 10485760) {
						res.status(400).json({
							message: 'File size cannot be more than 10MB'
						});
					} else {
						uploadFile(
							files.file.path,
							req.user.teamName + '_abstract.pdf'
						)
							.then(() => {
								req.user.submitted = true;
								req.user.uploadLink =
									req.user.teamName + '_abstract.pdf';
								req.user.save();

								let log = new Log({
									time: new Date().getTime(),
									trigger: false,
									event:
										'<b>' +
										req.user.teamName +
										'</b> uploaded their abstract!'
								});
								log.save();

								res.status(200).json({ message: 'done' });
							})
							.catch(console.error);
					}
				} else {
					res.status(400).json({ message: 'no file attached' });
				}
			});
		}
	} else {
		res.status(401).end();
	}
});

app.get('/home', (req, res) => {
	if (req.isAuthenticated()) {
		if (!req.user.verified) {
			res.render('not-verified');
		} else {
			Chat.where({ teamName: req.user.teamName }).findOne((err, chat) => {
				if (err) {
					res.status(501);
					res.end('Error');
				} else if (chat) {
					if (req.user.teamConfirm) {
						totalCost =
							indCost + indCost * req.user.teamMembers.length;
					} else {
						totalCost = indCost + '/member';
					}
					const currentTime = new Date().getTime();
					res.render('homenew', {
						team: req.user.teamName,
						chatId: chat._id,
						unread: chat.userUnread,
						teamConfirm: req.user.teamConfirm,
						payment: req.user.payment,
						submitted: req.user.submitted,
						status1: req.user.status1,
						totalCost: totalCost,
						teamConfirmDeadline: teamConfirmDeadline < currentTime,
						submissionDeadline: submissionDeadline < currentTime,
						round1Result: round1Result < currentTime,
						paymentDeadline: paymentDeadline < currentTime,
						round2Start: round2Start < currentTime,
						round2End: round2End < currentTime,
						round2Result: round2Result < currentTime,
						teamConfirmDate: teamConfirmDate,
						submissionDate: submissionDate,
						round1Date: round1Date,
						paymentDate: paymentDate,
						round2DateTime: round2DateTime,
						round2Link: round2Link,
						round2ResultTime: round2ResultTime
					});
				}
			});
		}
	} else {
		res.redirect('/login');
	}
});

app.get('/logout', (req, res) => {
	if (req.isAuthenticated()) {
		req.logout();
		res.redirect('/');
	} else {
		res.redirect('/');
	}
});

app.get('/login', (req, res) => {
	if (req.isAuthenticated()) {
		res.redirect('/home');
	} else {
		res.render('login');
	}
});

app.get('/forgot-password', (req, res) => {
	if (req.isAuthenticated()) {
		res.redirect('/home');
	} else if (req.session[process.env.RESET_SESSION_VAR]) {
		res.render('reset-form');
	} else {
		res.render('forgot-password');
	}
});

app.post('/forgot-password', async (req, res) => {
	if (req.isAuthenticated()) {
		res.redirect('/home');
	} else {
		const mailData = {
			email: req.body.username,
			code: Math.floor(Math.random() * 900000) + 100000
		};

		var mailStatus = await resetPassword(mailData);

		if (mailStatus == 1) {
			req.session[process.env.RESET_SESSION_VAR] = req.body.username;
		}

		let log = new Log({
			time: new Date().getTime(),
			trigger: false,
			event:
				'<b>' +
				req.body.username +
				'</b> requested forgot password email!'
		});
		log.save();

		res.send({ message: mailStatus });
	}
});

app.post('/reset-password', async (req, res) => {
	if (req.isAuthenticated() && req.session[process.env.RESET_SESSION_VAR]) {
		res.redirect('/home');
	} else {
		let patt = new RegExp(
			'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$'
		);
		if (
			req.body.password &&
			req.body.pwagain &&
			req.body.code &&
			req.body.password != '' &&
			req.body.pwagain != '' &&
			req.body.code != '' &&
			req.body.password === req.body.pwagain &&
			patt.test(req.body.password)
		) {
			User.where({
				username: req.session[process.env.RESET_SESSION_VAR]
			}).findOne((err, user) => {
				if (user.resetPw.code == req.body.code) {
					if (user.resetPw.available) {
						if (user.resetPw.time + 300000 > new Date().getTime()) {
							user.setPassword(req.body.password, (error) => {
								if (error) {
									res.send({ message: 5 });
									console.log(error);
								} else {
									let log = new Log({
										time: new Date().getTime(),
										trigger: false,
										event:
											'<b>' +
											req.session[
												process.env.RESET_SESSION_VAR
											] +
											'</b> reset their password!'
									});
									log.save();

									user.resetPw.available = false;
									user.save();
									req.session[
										process.env.RESET_SESSION_VAR
									] = null;

									res.send({ message: 1 });
								}
							});
						} else {
							req.session[process.env.RESET_SESSION_VAR] = null;
							res.send({ message: 4 });
						}
					} else {
						req.session[process.env.RESET_SESSION_VAR] = null;
						res.send({ message: 3 });
					}
				} else {
					res.send({ message: 2 });
				}
			});
		} else {
			res.send({ message: 0 });
		}
	}
});

app.get('/verify', (req, res) => {
	if (req.isAuthenticated()) {
		res.send('is isAuthenticated :)');
	} else {
		res.send('not authenticated');
	}
});

app.post('/login', (req, res) => {
	if (req.isAuthenticated()) {
		res.redirect('/home');
	} else if (
		!(req.body.username && req.body.password) ||
		req.body.username == '' ||
		req.body.password == ''
	) {
		res.redirect('/login');
	} else {
		const user = new User({
			username: req.body.username,
			password: req.body.password
		});

		req.login(user, (err) => {
			if (err) {
				console.log(err);
				res.send({ message: 'Incorrect Email Address or Password' });
			} else {
				passport.authenticate('local')(req, res, () => {
					let log = new Log({
						time: new Date().getTime(),
						trigger: false,
						event: '<b>' + req.body.username + '</b> logged in!'
					});
					log.save();

					res.send({ message: 'done' });
				});
			}
		});
	}
});

app.get('/signup', (req, res) => {
	if (req.isAuthenticated()) {
		res.redirect('/home');
	} else if (new Date().getTime() < regEndDate) {
		res.render('register');
	} else {
		res.render('registration-ended');
	}
});

app.post('/signup', createAccountLimiter, (req, res) => {
	if (req.isAuthenticated()) {
		res.status(404);
	} else if (
		!(
			req.body.password &&
			req.body.username &&
			req.body.leadername &&
			req.body.college &&
			req.body.contact &&
			req.body.team &&
			req.body.domain
		) ||
		req.body.password == '' ||
		req.body.username == '' ||
		req.body.leadername == '' ||
		req.body.college == '' ||
		req.body.contact == '' ||
		req.body.team == '' ||
		!(req.body.domain == 'S' || req.body.domain == 'H')
	) {
		res.status(401);
	} else if (req.body.password !== req.body.passwordagain) {
		res.send({ message: 'Passwords do not match' });
	} else {
		let patt = new RegExp(
			'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$'
		);
		if (patt.test(req.body.password)) {
			let domain = false;
			if (req.body.domain == 'S') {
				domain = true;
			}

			User.register(
				{
					username: String(req.body.username)
						.replace(/&/g, '&amp;')
						.replace(/</g, '&lt;')
						.replace(/>/g, '&gt;')
						.replace(/"/g, '&quot;'),
					leaderName: String(req.body.leadername)
						.replace(/&/g, '&amp;')
						.replace(/</g, '&lt;')
						.replace(/>/g, '&gt;')
						.replace(/"/g, '&quot;'),
					leaderCollege: String(req.body.college)
						.replace(/&/g, '&amp;')
						.replace(/</g, '&lt;')
						.replace(/>/g, '&gt;')
						.replace(/"/g, '&quot;'),
					leaderContact: String(req.body.contact)
						.replace(/&/g, '&amp;')
						.replace(/</g, '&lt;')
						.replace(/>/g, '&gt;')
						.replace(/"/g, '&quot;'),
					teamName: String(req.body.team)
						.replace(/&/g, '&amp;')
						.replace(/</g, '&lt;')
						.replace(/>/g, '&gt;')
						.replace(/"/g, '&quot;'),
					verified: false,
					domain: domain,
					teamMembers: []
				},
				req.body.password,
				(err, user) => {
					if (err) {
						if (err.name === 'UserExistsError') {
							res.send({
								message: 'User already registered!'
							});
						} else {
							if (
								err.name === 'MongoError' &&
								err.code === 11000
							) {
								res.send({
									message: 'Team Name already taken'
								});
							} else if (
								err.errors.username !== undefined &&
								err.errors.username.name === 'ValidatorError'
							) {
								res.send({
									message: err.errors.username.message
								});
							} else if (
								err.errors.teamName !== undefined &&
								err.errors.teamName.name === 'ValidatorError'
							) {
								res.send({
									message:
										'Team Name should contain minimum 4 characters!'
								});
							} else {
								console.log(JSON.stringify(err));
								res.send({ message: 'Server Error' });
							}
						}
					} else {
						// eslint-disable-next-line no-undef
						var verifyURL = CryptoJS.Rabbit.encrypt(
							req.body.username + ' ' + new Date().getTime(),
							process.env.VERIFY_ENCRYPTION
						).toString();

						verifyURL =
							req.headers.host +
							'/verifymail?v=' +
							encodeURIComponent(verifyURL);

						const mailData = {
							email: req.body.username,
							teamName: req.body.team,
							url: verifyURL
						};

						verifyEmail(mailData);

						Broadcast.find(
							{},
							{ _id: 0, time: 1, message: 1, sender: 1 },
							(err, broadcast) => {
								if (err) {
									console.log(err);
								} else {
									if (broadcast.length == 0) {
										const chat = new Chat({
											teamName: req.body.team,
											messages: []
										});
										chat.save();
									} else {
										const chat = new Chat({
											teamName: req.body.team,
											messages: broadcast,
											userUnread: true
										});
										chat.save();
									}
								}
							}
						);

						passport.authenticate('local')(req, res, () => {
							let log = new Log({
								time: new Date().getTime(),
								trigger: false,
								event:
									'<b>' +
									req.user.teamName +
									'</b> registered!'
							});
							log.save();

							res.send({ message: 'done' });
						});
					}
				}
			);
		} else {
			res.send({ message: "Password doesn't satisfy the conditions!" });
		}
	}
});

app.get('/verifymail', (req, res) => {
	// eslint-disable-next-line no-undef
	const decryptedVerification = CryptoJS.Rabbit.decrypt(
		req.query.v,
		process.env.VERIFY_ENCRYPTION
	)
		.toString(CryptoJS.enc.Utf8)
		.split(' ');

	if (decryptedVerification.length != 2) {
		res.status(404);
		res.end();
	}

	const email = decryptedVerification[0];
	const time = parseInt(decryptedVerification[1]);

	if (req.isAuthenticated() && req.user.username != email) {
		res.status(404);
		res.end();
	} else if (time + 24 * 60 * 60 * 1000 < new Date().getTime()) {
		res.status(401);
		res.render('verification-expired');
		res.end();
	} else {
		User.where({ username: email }).findOne((err, user) => {
			if (err) {
				res.status(500);
				res.end('Server Error!');
			} else if (user) {
				if (user.verified) {
					res.redirect('/home');
					res.end();
				} else {
					user.verified = true;
					user.save();

					let log = new Log({
						time: new Date().getTime(),
						trigger: false,
						event:
							'<b>' + email + '</b> verified email successfully!'
					});
					log.save();

					res.redirect('/login');
				}
			} else {
				res.status(500);
				res.end('Server Error!');
			}
		});
	}
});

app.post('/resend-verification', async (req, res) => {
	if (req.isAuthenticated()) {
		// eslint-disable-next-line no-undef
		var verifyURL = CryptoJS.Rabbit.encrypt(
			req.user.username + ' ' + new Date().getTime(),
			process.env.VERIFY_ENCRYPTION
		).toString();

		verifyURL =
			req.headers.host + '/verifymail?v=' + encodeURIComponent(verifyURL);

		const mailData = {
			email: req.user.username,
			teamName: req.user.teamName,
			url: verifyURL
		};

		var mailStatus = await verifyEmail(mailData);

		let log = new Log({
			time: new Date().getTime(),
			trigger: false,
			event:
				'<b>' +
				req.user.teamName +
				'</b> requested resending email verification link!'
		});
		log.save();

		res.send({ message: mailStatus });
		res.end();
	} else {
		res.status(401);
		res.end('Unauthorised!');
	}
});

app.get('/csi-admin-login', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		res.redirect('/admin-panel');
	} else {
		res.render('admin-login');
	}
});

app.post('/csi-admin-login', (req, res) => {
	// eslint-disable-next-line no-undef
	if (req.body.secret == process.env.ADMIN_LOGIN) {
		// eslint-disable-next-line no-undef
		req.session[process.env.ADMIN_SESSION_VAR] =
			process.env.ADMIN_SESSION_VAL;

		req.session[process.env.ADMIN_NAME] = req.body.name;

		let log = new Log({
			time: new Date().getTime(),
			trigger: true,
			event: req.body.name + ' (Admin) login.'
		});
		log.save();

		res.redirect('/admin-panel');
	} else {
		res.redirect('/csi-admin-login');
	}
});

app.get('/admin-panel', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		Chat.where({}).find((err, chats) => {
			if (err) {
				res.send('Errorrrr!');
			} else {
				var unread = chats.filter((chat) => {
					return chat.adminUnread;
				});
				var read = chats.filter((chat) => {
					return !chat.adminUnread;
				});
				var newChat = unread.concat(read);
				// eslint-disable-next-line no-undef
				res.render('admin-panel', {
					adminEvent: process.env.ADMIN_EVENT,
					chats: newChat
				});
				res.end();
			}
		});
	} else {
		res.redirect('/csi-admin-login');
	}
});

app.get('/ranking/:domain', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		let dom;
		let flag = true;
		if (req.params.domain == 's') {
			dom = true;
		} else if (req.params.domain == 'h') {
			dom = false;
		} else {
			res.redirect('/');
			flag = false;
		}
		if (flag) {
			User.find({ graded2: true, domain: dom })
				.sort({ status2: -1 })
				.exec((err, users) => {
					if (err) {
						res.status(500).send('There was an error!');
					} else if (users) {
						res.render('ranking', { users: users });
					} else {
						res.status(500).send('There was an error!');
					}
				});
		}
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.get('/chats/:chatId', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		Chat.findById(req.params.chatId, (err, chat) => {
			if (err) {
				res.status(404);
				res.end('Not Found');
			} else if (chat) {
				// eslint-disable-next-line no-undef
				res.render('admin-chat-box', {
					adminEvent: process.env.ADMIN_EVENT,
					chat: chat
				});
			}
		});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.get('/user-chat', (req, res) => {
	if (req.isAuthenticated()) {
		Chat.where({ teamName: req.user.teamName }).findOne((err, chat) => {
			if (err) {
				res.end('Error');
			} else if (chat) {
				res.render('user-chat-box-new', { chat: chat });
			}
		});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.get('/admin-logout', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		// eslint-disable-next-line no-undef
		req.session[process.env.ADMIN_SESSION_VAR] = null;

		res.redirect('/');
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.get('/logs-user', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		Log.where({ trigger: false })
			.sort({ _id: -1 })
			.find((err, logs) => {
				if (err) {
					res.send('Error');
				} else {
					res.render('logs', { logs: logs, trigger: 'User' });
				}
			});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.get('/logs-admin', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		Log.where({ trigger: true })
			.sort({ _id: -1 })
			.find((err, logs) => {
				if (err) {
					res.send('Error');
				} else {
					res.render('logs', { logs: logs, trigger: 'Admin' });
				}
			});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.get('/admin-broadcast', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		// eslint-disable-next-line no-undef
		res.render('broadcast', { broadcast: process.env.ADMIN_BROADCAST });
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.get('/delete-broadcast', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		Broadcast.where({}).find((err, messages) => {
			if (err) {
				res.send('Error');
			} else {
				res.render('deleteBroadcast', { messages: messages });
			}
		});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.get('/participants', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		User.where({}).find((err, users) => {
			if (err) {
				res.send('Error');
			} else {
				res.render('participants', { users: users });
			}
		});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.get('/verified-users', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		User.where({ verified: true }).find((err, users) => {
			if (err) {
				res.send('Error');
			} else {
				res.render('verified', { users: users });
			}
		});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.get('/unpaid', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		User.where({ status1: true, payment: false }).find((err, users) => {
			if (err) {
				res.send('Error');
			} else {
				res.render('unpaid', { unpaid: users });
			}
		});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.get('/paid', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		User.where({ status1: true, payment: true }).find((err, users) => {
			if (err) {
				res.send('Error');
			} else {
				res.render('paid', { paid: users });
			}
		});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.get('/round1u', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		User.where({ submitted: true, graded1: false }).find((err, users) => {
			if (err) {
				res.send('Error');
			} else {
				res.render('round1u', { ungraded: users });
			}
		});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.get('/round2u', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		User.where({ payment: true, graded2: false, status1: true }).find(
			(err, users) => {
				if (err) {
					res.send('Error');
				} else {
					res.render('round2u', { ungraded: users });
				}
			}
		);
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.get('/round1g', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		User.where({ graded1: true }).find((err, users) => {
			if (err) {
				res.send('Error');
			} else {
				res.render('round1g', { graded: users });
			}
		});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.get('/round2g', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		User.where({ graded2: true }).find((err, users) => {
			if (err) {
				res.send('Error');
			} else {
				res.render('round2g', { graded: users });
			}
		});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.post('/delete-broadcast', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		const time = Number(req.body.time);
		Broadcast.deleteOne({ time: time }, (err) => {
			if (err) {
				res.send({ message: 'no' });
			} else if (req.body.mode != '2') {
				Chat.updateMany(
					{ 'messages.time': time, 'messages.sender': true },
					{
						$set: { 'messages.$.message': '<i>Message Deleted</i>' }
					},
					(err) => {
						if (err) {
							res.send({ message: 'no' });
						} else {
							let log = new Log({
								time: new Date().getTime(),
								trigger: true,
								event:
									req.session[process.env.ADMIN_NAME] +
									' (Admin) deleted broadcast message <b>with</b> evidence!'
							});
							log.save();
							res.send({ message: 'done' });
						}
					}
				);
			} else {
				Chat.updateMany(
					{},
					{ $pull: { messages: { time: time, sender: true } } },
					{ multi: false },
					(err) => {
						if (err) {
							res.send({ message: 'no' });
						} else {
							let log = new Log({
								time: new Date().getTime(),
								trigger: true,
								event:
									req.session[process.env.ADMIN_NAME] +
									' (Admin) deleted broadcast message <b>without</b> evidence!'
							});
							log.save();

							res.send({ message: 'done' });
						}
					}
				);
			}
		});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.post('/changeFee', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		let key;
		if (req.body.key == 'true') {
			key = true;
		} else {
			key = false;
		}
		User.findById(req.body.id, (err, user) => {
			if (err) {
				console.log(err);
				res.send('Error');
			} else {
				if (user.status1) {
					user.payment = key;
					user.graded2 = false;
					user.status2 = 0;
					user.save();

					let log = new Log({
						time: new Date().getTime(),
						trigger: true,
						event:
							req.session[process.env.ADMIN_NAME] +
							' (Admin) changed payment status of <b>' +
							user.teamName +
							'</b> to <b>' +
							req.body.key +
							'</b>'
					});
					log.save();

					res.send({ message: 'done' });
				} else {
					res.send({ message: 'nope' });
				}
			}
		});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.post('/changeR1', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		let key;
		if (req.body.key == 'true') {
			key = true;
		} else {
			key = false;
		}
		User.findById(req.body.id, (err, user) => {
			if (err) {
				console.log(err);
				res.send('Error');
			} else {
				if ((!key || user.submitted) && !user.payment) {
					user.graded1 = true;
					user.status1 = key;
					user.save();

					let log = new Log({
						time: new Date().getTime(),
						trigger: true,
						event:
							req.session[process.env.ADMIN_NAME] +
							' (Admin) changed ROUND 1 status of <b>' +
							user.teamName +
							'</b> to <b>' +
							req.body.key +
							'</b>'
					});
					log.save();

					res.send({ message: 'done' });
				} else if (user.payment) {
					res.send({ message: 'nope' });
				} else {
					res.send({ message: 'no' });
				}
			}
		});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.post('/changeR2', (req, res) => {
	// eslint-disable-next-line no-undef
	if (
		req.session[process.env.ADMIN_SESSION_VAR] &&
		req.session[process.env.ADMIN_SESSION_VAR] ==
			process.env.ADMIN_SESSION_VAL
	) {
		let key = parseInt(req.body.key);

		User.findById(req.body.id, (err, user) => {
			if (err) {
				console.log(err);
				res.send('Error');
			} else {
				if (user.payment && user.status1) {
					user.graded2 = true;
					user.status2 = key;
					user.save();

					let log = new Log({
						time: new Date().getTime(),
						trigger: true,
						event:
							req.session[process.env.ADMIN_NAME] +
							' (Admin) changed ROUND 2 status of <b>' +
							user.teamName +
							'</b> to <b>' +
							req.body.key +
							'</b>'
					});
					log.save();

					res.send({ message: 'done' });
				} else {
					res.send({ message: 'no' });
				}
			}
		});
	} else {
		res.status(401);
		res.end('Unauthorised');
	}
});

app.use((req, res, next) => {
	res.status(404).render('error-404');
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, console.log(`Server started on port ${PORT}`));
