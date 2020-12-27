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
			res.render("home",{team: req.user.teamName});
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
})


app.listen(3000, () => {
	console.log('Listening to port 3000');
});
