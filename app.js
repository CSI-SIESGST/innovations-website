require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
require('ejs');
const session = require('express-session');
const passport = require('passport');
require('dotenv').config();
const CryptoJS = require('crypto-js');

const verifyEmail = require('./functions/verifyEmail');

require('./db/mongoose');
const User = require('./schema/userSchema');
const Chat = require('./schema/chatSchema');

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static('public'));

app.use(session({
	// eslint-disable-next-line no-undef
	secret: process.env.SECRET_KEY,
	resave: false,
	saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
	done(null, user.id);
});

passport.deserializeUser(function(id, done) {
	User.findById(id, function(err, user) {
		done(err, user);
	});
});


const server = require('http').Server(app);
const io = require('socket.io')(server);


io.on('connection', socket => {

    // eslint-disable-next-line no-undef
    socket.on(process.env.ADMIN_EVENT, () => {
        // eslint-disable-next-line no-undef
        socket.join(process.env.ADMIN_ROOM);
	})
	
	socket.on('join-room', (chatsId) => {
		socket.join(chatsId);
	})

	socket.on('user-read', (chatsId, teamName) => {
		Chat.findById(chatsId, (err,chat) => {
			if(err)
            {
                // eslint-disable-next-line no-undef
                socket.to(chatsId).emit('refresh');
			}
			else
			{
				if(chat.userUnread)
				{
					chat.userUnread = false;
					chat.save();
				}
			}
		})

		// eslint-disable-next-line no-undef
		socket.to(process.env.ADMIN_ROOM).emit('user-read', teamName)
	})

    socket.on('msg-to-admin', (teamName, message, chatsId) => {
        Chat.where({teamName: teamName}).findOne((err,chat) => {
            if(err)
            {
                // eslint-disable-next-line no-undef
                socket.to(chatsId).emit('refresh');
            }
            else
            {
                // eslint-disable-next-line no-undef
                socket.to(process.env.ADMIN_ROOM).emit('new-msg', teamName, message)

                chat.messages.push({time: new Date().getTime(), message: message, sender: false})
                chat.adminUnread = true;

                chat.save();
            }
        })
    })

    socket.on('msg-to-user', (teamName, message, chatsId) => {
        Chat.where({teamName: teamName}).findOne((err,chat) => {
            if(err)
            {
                // eslint-disable-next-line no-undef
                socket.to(process.env.ADMIN_ROOM).emit('refresh');
            }
            else
            {
                // eslint-disable-next-line no-undef
                socket.to(chatsId).emit('new-msg', teamName, message)

                chat.messages.push({time: new Date().getTime(), message: message, sender: true})
                chat.userUnread = true;

                chat.save();
            }
        })
    })

})


app.get("/", (req,res) => {

	res.send('Hello World!');

});

app.get("/home", (req,res) => {

	if(req.isAuthenticated())
	{
		if(!req.user.verified)
		{
			res.status(200)
			res.end('Not Verified')
		}
		else
		{
			Chat.where({teamName: req.user.teamName}).findOne((err,chat) => {
				if(err)
				{
					res.status(501);
					res.end('Error');
				}
				else if(chat)
				{
					res.render("home",{team: req.user.teamName, chatId: chat._id, read: chat.userUnread});
				}
			})
		}
		
	}
	else
	{
		res.redirect("/login");
	}

});

app.get("/logout", (req,res) => {
	if(req.isAuthenticated())
	{
		req.logout();
		res.redirect('/');
	}
	else
	{
		res.redirect('/');
	}
})

app.get("/login", (req,res) => {

	if(req.isAuthenticated())
	{
		res.redirect("home");
	}
	else
	{
		res.render("login");
	}

});

app.get('/verify', (req,res) => {
	if(req.isAuthenticated()){
		res.send('is isAuthenticated :)');
	}
	else{
		res.send('not authenticated');
	}
});

app.post('/login', (req,res) => {

	if(req.isAuthenticated())
	{
		res.redirect("home");
	}
	else
	{
		const user = new User({
			username: req.body.username,
			password: req.body.password
		});

		req.login(user, (err) => {

			if(err)
			{
				console.log(err);
				res.send({message: "Incorrect Email Address or Password"})
			}
			else
			{
				passport.authenticate("local")(req,res,() => {
					res.send({message: "done"});
				});
			}

		});
	}
});

app.get("/signup", (req,res) => {

	if(req.isAuthenticated())
	{
			res.redirect('/home');
	}
	else
	{
		res.render("signup");
	}

});

app.post('/signup', (req,res) => {

	if(req.isAuthenticated())
	{
		res.status(404);
	}
	else
	{
		let patt = new RegExp("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$");
		if(patt.test(req.body.password))
		{
			User.register(
				{
					username: req.body.username,
					teamName: req.body.team,
					verified: false,
					teamMembers: []
				// eslint-disable-next-line no-unused-vars
				}, req.body.password, (err, user) => {
				if(err)
				{
					if(err.name === "UserExistsError")
					{
						User.where({username: req.body.username}).findOne((err,user) => {
							if(err)
							{
								console.log(err)
								res.send({message: "Server Error"});
							}
							else
							{
								if(user.verified)
								{
									res.send({message: 'User already registered!'})
								}
								else
								{
									res.send({message: 'User already registered, but not verified!'})
									// User.deleteOne({username: req.body.username}, delErr => {
									// 	if(delErr)
									// 	{
									// 		console.log(delErr);
									// 		res.send({message: "Server Error"});
									// 	}
									// 	else
									// 	{
									// 		User.register(
									// 			{
									// 				username: req.body.username,
									// 				teamName: req.body.team,
									// 				verified: false,
									// 				verificationUrl: uuidv4(),
									// 				pwChangeUrl: '0'
									// 			}, req.body.password, (err, user) => {
									// 				if(err)
									// 				{
									// 					if(err.name === 'MongoError' && err.code === 11000)
									// 					{
									// 						res.send({message: "Team Name already taken"});
									// 					}
									// 					else if(err.errors.username !== undefined && err.errors.username.name === 'ValidatorError')
									// 					{
									// 						res.send({message: err.errors.username.message});
									// 					}
									// 					else if(err.errors.teamName !== undefined && err.errors.teamName.name === 'ValidatorError')
									// 					{
									// 						res.send({message: 'Team Name should contain minimum 4 characters!'});
									// 					}
									// 					else
									// 					{
									// 						console.log(JSON.stringify(err))
									// 						res.send({message: "Server Error"});
									// 					}
									// 				}
									// 				else
									// 				{
									// 					passport.authenticate("local")(req,res,() => {
									// 						res.send({message: 'done'});
									// 					});
									// 				}
									// 			}
									// 		)
									// 	}
									// })
								}
							}
						})
					}
					else
					{
						if(err.name === 'MongoError' && err.code === 11000)
						{
							res.send({message: "Team Name already taken"});
						}
						else if(err.errors.username !== undefined && err.errors.username.name === 'ValidatorError')
						{
							res.send({message: err.errors.username.message});
						}
						else if(err.errors.teamName !== undefined && err.errors.teamName.name === 'ValidatorError')
						{
							res.send({message: 'Team Name should contain minimum 4 characters!'});
						}
						else
						{
							console.log(JSON.stringify(err))
							res.send({message: "Server Error"});
						}

					}
				}
				else
				{

					// eslint-disable-next-line no-undef
					var verifyURL = CryptoJS.Rabbit.encrypt(req.body.username+' '+ new Date().getTime(), process.env.VERIFY_ENCRYPTION).toString();

					verifyURL = req.headers.host+'/verifymail?v='+encodeURIComponent(verifyURL);

					const mailData = {
						email: req.body.username,
						teamName: req.body.team,
						url: verifyURL
					}

					verifyEmail(mailData)

					// eslint-disable-next-line no-unused-vars
					const chat = new Chat({teamName: req.body.team, messages:[]});
					chat.save()

					passport.authenticate("local")(req,res,() => {
						
						res.send({message: 'done'});

					});
				}
			});
		}
		else{
			res.send({message: 'Password doesn\'t satisfy the conditions!'})
		}
	}

});

app.get('/verifymail', (req,res) => {
	// eslint-disable-next-line no-undef
	const decryptedVerification = CryptoJS.Rabbit.decrypt(req.query.v, process.env.VERIFY_ENCRYPTION).toString(CryptoJS.enc.Utf8).split(' ');

	if(decryptedVerification.length != 2)
	{
		res.status(404);
		res.end();
	}

	const email = decryptedVerification[0]
	const time = parseInt(decryptedVerification[1])

	if(req.isAuthenticated() && req.user.username!=email)
	{
		res.status(404);
		res.end();
	}

	if(time+(24*60*60*1000) < new Date().getTime())
	{
		res.status(401);
		res.end('time-up')
	}

	User.where({username: email}).findOne((err,user) => {
		if(err)
		{
			res.status(404);
			res.end('Server Error!');
		}
		else
		{
			if(user.verified)
			{
				res.redirect('/home')
				res.end();
			}
			else
			{
				user.verified = true;
				user.save();
				res.redirect('/login')
			}
		}
	})
});

app.post('/resend-verification', async (req,res) => {
	if(req.isAuthenticated())
	{
		// eslint-disable-next-line no-undef
		var verifyURL = CryptoJS.Rabbit.encrypt(req.user.username+' '+ new Date().getTime(), process.env.VERIFY_ENCRYPTION).toString();

		verifyURL = req.headers.host+'/verifymail?v='+encodeURIComponent(verifyURL);

		const mailData = {
			email: req.user.username,
			teamName: req.user.teamName,
			url: verifyURL
		}

		var mailStatus = await verifyEmail(mailData);

		res.send({message: mailStatus});
		res.end();
	}
	else
	{
		res.status(401);
		res.end('Unauthorised!');
	}
});

app.get('/csi-admin-login', (req,res) => {
	// eslint-disable-next-line no-undef
	if(req.session[process.env.ADMIN_SESSION_VAR] && req.session[process.env.ADMIN_SESSION_VAR] == process.env.ADMIN_SESSION_VAL)
	{
		res.redirect('/admin-panel');
	}
	else
	{
		res.render('admin-login');
	}
});

app.post('/csi-admin-login', (req,res) => {
	// eslint-disable-next-line no-undef
	if(req.body.secret == process.env.ADMIN_LOGIN)
	{
		// eslint-disable-next-line no-undef
		req.session[process.env.ADMIN_SESSION_VAR] = process.env.ADMIN_SESSION_VAL;
		res.redirect('/admin-panel');
	}
	else
	{
		res.redirect('/csi-admin-login');
	}
})

app.get('/admin-panel', (req,res) => {
	// eslint-disable-next-line no-undef
	if(req.session[process.env.ADMIN_SESSION_VAR] && req.session[process.env.ADMIN_SESSION_VAR] == process.env.ADMIN_SESSION_VAL)
	{
		Chat.where({}).find((err,chats) => {
			if(err)
			{
				res.send('Errorrrr!')
			}
			else
			{
				var unread = chats.filter(chat => {
					return chat.adminUnread
				})
				var read = chats.filter(chat => {
					return !chat.adminUnread
				})
				var newChat = unread.concat(read)
				// eslint-disable-next-line no-undef
				res.render('admin-panel', {adminEvent: process.env.ADMIN_EVENT, chats: newChat});
				res.end();
			}
		})
		
	}
	else
	{
		res.redirect('/csi-admin-login');
	}
})

app.get('/chats/:chatId', (req,res) => {
	// eslint-disable-next-line no-undef
	if(req.session[process.env.ADMIN_SESSION_VAR] && req.session[process.env.ADMIN_SESSION_VAR] == process.env.ADMIN_SESSION_VAL)
	{
		Chat.findById(req.params.chatId, (err,chat) => {
			if(err)
			{
				res.status(404)
				res.end('Not Found');
			}
			else if(chat)
			{
				// eslint-disable-next-line no-undef
				res.render('admin-chat-box', {adminEvent: process.env.ADMIN_EVENT, chat: chat})
			}
		})
	}
	else
	{
		res.redirect('/csi-admin-login');
	}
})

app.get('/user-chat', (req,res) => {
	if(req.isAuthenticated())
	{
		Chat.where({teamName: req.user.teamName}).findOne((err,chat) => {
			if(err)
			{
				res.end('Error')
			}
			else if(chat)
			{
				res.render('user-chat-box', {chat: chat})
			}
		})
	}
	else
	{
		res.status(401);
		res.end('Unauthorised')
	}
})


server.listen(3000, () => {
	console.log('Listening to port 3000');
});
