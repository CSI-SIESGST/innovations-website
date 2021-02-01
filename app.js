require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
require('ejs');
const session = require('express-session');
const passport = require('passport');
const CryptoJS = require('crypto-js');
const rateLimit = require('express-rate-limit');

const admin = require('firebase-admin');
const formidable = require('formidable');

const verifyEmail = require('./functions/verifyEmail');

require('./db/mongoose');
const User = require('./schema/userSchema');
const Chat = require('./schema/chatSchema');
const Broadcast = require('./schema/broadcastSchema');
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
	storageBucket: 'innovations-csi.appspot.com'
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

const app = express();

const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100 // limit each IP to 100 requests per windowMs
});

app.set('trust proxy', '127.0.0.1');
app.use(limiter);

app.set('view engine', 'ejs');

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
		Chat.where({ teamName: teamName }).findOne((err, chat) => {
			if (err) {
				// eslint-disable-next-line no-undef
				socket.to(chatsId).emit('refresh');
			} else {
				var time = new Date().getTime();

				callback({ time: time });

				// eslint-disable-next-line no-undef
				socket
					.to(process.env.ADMIN_ROOM)
					.emit('new-msg', teamName, message, time);

				chat.messages.push({
					time: time,
					message: message,
					sender: false
				});
				chat.adminUnread = true;

				chat.save();
			}
		});
	});

	socket.on('msg-to-user', (teamName, message, chatsId, callback) => {
		Chat.where({ teamName: teamName }).findOne((err, chat) => {
			if (err) {
				// eslint-disable-next-line no-undef
				socket.to(process.env.ADMIN_ROOM).emit('refresh');
			} else {
				var time = new Date().getTime();

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
	socket.on(process.env.ADMIN_BROADCAST, (message, callback) => {
		message = '<small><b>Broadcast Message</b></small><br>' + message;

		var time = new Date().getTime();

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
	});
});

app.get('/', (req, res) => {
	if (req.isAuthenticated()) {
		res.render('index', { team: req.user.teamName });
	} else {
		res.render('index', { team: null });
	}
});

app.get('/info', (req, res) => {
	if (req.isAuthenticated()) {
		res.render('info', { team: req.user.teamName });
	} else {
		res.render('info', { team: null });
	}
});

app.get('/members', (req, res) => {
	if (req.isAuthenticated()) {
		if (!req.user.verified) {
			res.render('not-verified');
		} else {
			res.render('members');
		}
	} else {
		res.render('login');
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
					res.render('homenew', {
						team: req.user.teamName,
						chatId: chat._id,
						unread: chat.userUnread
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
		res.redirect('home');
	} else {
		res.render('login');
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
					res.send({ message: 'done' });
				});
			}
		});
	}
});

app.get('/signup', (req, res) => {
	if (req.isAuthenticated()) {
		res.redirect('/home');
	} else {
		res.render('register');
	}
});

app.post('/signup', (req, res) => {
	if (req.isAuthenticated()) {
		res.status(404);
	} else if (
		!(
			req.body.password &&
			req.body.username &&
			req.body.leadername &&
			req.body.college &&
			req.body.contact &&
			req.body.team
		) ||
		req.body.password == '' ||
		req.body.username == '' ||
		req.body.leadername == '' ||
		req.body.college == '' ||
		req.body.contact == '' ||
		req.body.team == ''
	) {
		res.status(404);
	} else if (req.body.password !== req.body.passwordagain) {
		res.send({ message: 'Passwords do not match' });
	} else {
		let patt = new RegExp(
			'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$'
		);
		if (patt.test(req.body.password)) {
			User.register(
				{
					username: req.body.username,
					leaderName: req.body.leadername,
					leaderCollege: req.body.college,
					leaderContact: req.body.contact,
					teamName: req.body.team,
					verified: false,
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
	}

	if (time + 24 * 60 * 60 * 1000 < new Date().getTime()) {
		res.status(401);
		res.render('verification-expired');
	}

	User.where({ username: email }).findOne((err, user) => {
		if (err) {
			res.status(404);
			res.end('Server Error!');
		} else {
			if (user.verified) {
				res.redirect('/home');
				res.end();
			} else {
				user.verified = true;
				user.save();
				res.redirect('/login');
			}
		}
	});
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
		res.redirect('/csi-admin-login');
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
		res.redirect('/csi-admin-login');
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
		User.where({ _id: req.body.id }).updateOne({ payment: key }, (err) => {
			if (err) {
				console.log(err);
				res.send('Error');
			} else {
				res.send({ message: 'done' });
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
				if (!key || user.submitted) {
					user.graded1 = true;
					user.status1 = key;
					user.save();
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
				if (user.status1) {
					user.graded2 = true;
					user.status2 = key;
					user.save();
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

app.post('/upload', (req, res) => {
	var form = new formidable.IncomingForm();
	form.parse(req, function (err, fields, files) {
		if (files.file) {
			uploadFile(files.file.path, files.file.name)
				.then(res.status(200).json({ msg: 'file uploaded' }))
				.catch(console.error);
		} else {
			res.status(400).json({ msg: 'no file attached' });
		}
	});
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, console.log(`Server started on port ${PORT}`));
