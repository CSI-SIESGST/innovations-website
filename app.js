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
const db = admin.firestore();

const app = express();

app.set('view engine', 'ejs');
//app.engine("html", require("ejs").renderFile);

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
	res.render('login.ejs');
});

app.get('/signup', (req, res) => {
	res.render('signup.ejs');
});

var data = {};

app.get('/home', (req, res) => {
	const sessionCookie = req.cookies.session || "";

	admin
		.auth()
		.verifySessionCookie(sessionCookie, true)
		.then(async (user) => {
			console.log(user.uid);
			db.collection('users').where('userId', '==', user.uid)
				.get()
				.then((querySnapshot) => {
					console.log(querySnapshot);
					querySnapshot.forEach((doc) => {
						console.log(doc.id, " => ", doc.data());
						data = doc.data();
						console.log(data.teamName);
					});
					res.render('home.ejs', {"team": data.teamName});
				})
				.catch((err) => {
					console.log("Error getting data");
					res.render('home.ejs');
				})
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