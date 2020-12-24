require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const session = require('express-session');
const passport = require('passport');

require('dotenv').config();

const mongoose = require('./db/mongoose');
const User = require('./schema/userSchema');

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static('public'));

app.use(session({
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
		res.render("home",{team: req.user.teamName});
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
		res.redirect("/home");
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
					pwChangeReq: new Date().getTime()
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


app.listen(3000, () => {
	console.log('Listening to port 3000');
});
