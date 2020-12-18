const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const cookieParser = require('cookie-parser');
const admin = require('firebase-admin');
const csrf  = require('csurf');

const serviceAccount = require("./serviceAccountKey.json");

admin.initializeApp({
	credential: admin.credential.cert(serviceAccount)
});

const csrfMiddleware = csrf({ cookie: true});

const app = express();

//app.set('view engine', 'ejs');
app.engine("html", require("ejs").renderFile);

app.use(express.static('static'));
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(csrfMiddleware);

app.all("*", (req, res, next) => {
	res.cookie("XSRF-TOKEN", req.csrfToken());
	next();
})

app.get("/", (req,res) => {
	res.send('Hello World!');
});

app.get("/login", (req, res) => {
	res.render('login.html');
});

app.get('/signup', (req, res) => {
	res.render('signup.html');
});

app.get('/home', (req, res) => {
	const sessionCookie = req.cookies.session || "";

	admin
		.auth()
		.verifySessionCookie(sessionCookie, true)
		.then(() => {
			res.render('home.html');
		})
		.catch((err) => {
			res.redirect('/login')
		});
});

app.post('/sessionLogin', (req, res) => {
	const idToken = req.body.idToken.toString();

	const expiresIn = 60 * 60 * 2 * 1000;

	admin
		.auth()
		.createSessionCookie(idToken, {expiresIn})
		.then(
			(sessionCookie) => {
				const options = {maxAge: expiresIn, httpOnly: true};
				res.cookie("session", sessionCookie, options);
				res.end(JSON.stringify({ status: "success"}));
			},
			(error) => {
				res.status(401).send("UNAUTHORIZED REQUEST");
			}
		);
});

app.get('/sessionLogout', (req, res) => {
	res.clearCookie("session");
	res.redirect('/login');
});

app.listen(4000, () => {
	console.log('Listening on port 4000');
});