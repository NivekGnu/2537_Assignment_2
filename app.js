require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const Joi = require('joi');

const port = process.env.PORT || 3000;
const app = express();

const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = require('./databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
});

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore,
	saveUninitialized: false, 
	resave: false,
    cookie: {maxAge: expireTime}
}
));

app.use(express.urlencoded({extended: false}));

app.use(express.static(__dirname + "/public"));

app.set('view engine', 'ejs');

const navLinks = [
    {name: 'Home', url: '/'},
    {name: 'Members', url: '/members'},
    {name: 'Admin', url: '/admin'},
    {name: '404', url: '/404'},
    {name: 'Log Out', url: '/logout'}
];

app.get('/', (req,res) => {
    if(req.session.authenticated) {
        res.render("homepage", {title: "Home", navLinks: navLinks, name: req.session.user.name})
        
    } else {
        res.render("welcome", {title: "Welcome", navLinks: navLinks,})
    }
});

app.get('/signup', (req,res) => {
    res.render("signup", {title: 'Sign Up', navLinks: navLinks, errorMessage: null});
});

app.post('/signupSubmit', async (req,res) => {
    const {name, email, password} = req.body;

    if (!name) {
        res.render("signup", {title: 'Sign Up', navLinks: navLinks, errorMessage: "Name can not be empty"});
        return;
    }

    if (!email) {
        res.render("signup", {title: 'Sign Up', navLinks: navLinks, errorMessage: "Email can not be empty"});
        return;
    }

    if (!password) {
        res.render("signup", {title: 'Sign Up', navLinks: navLinks, errorMessage: "Password can not be empty"});
        return;
    }

    const schema = Joi.object(
    {
            name: Joi.string().alphanum().max(30).required(),
            email:  Joi.string().email().required(),
            password: Joi.string().max(30).required()
    });

    const validationResult = schema.validate(req.body);

    if(validationResult.error) {
        res.render("signup", {title: 'Sign Up', navLinks: navLinks, errorMessage: validationResult.error.details[0].message});
        return;
    }

    const existingEmail = await userCollection.findOne({email: email});
    if (existingEmail) {
        res.render("signup", {title: 'Sign Up', navLinks: navLinks, errorMessage: "Email already exists"});
        return;
    }

    const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);

    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword,
        userType: 'member'
        });

    console.log('User successfully created');

    req.session.user = {
        name: name,
        email: email,
        userType: 'member'
    }

    req.session.authenticated = true;

    res.redirect('/members');
});

app.get('/login', (req,res) => {
    res.render("login", {title: "Log In", navLinks: navLinks, errorMessage: null});
});

app.post('/loginSubmit', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

    if (!email) {
        res.render("login", {title: 'Log In', navLinks: navLinks, errorMessage: "Email can not be empty"});
        return;
    }

    if (!password) {
        res.render("login", {title: 'Log In', navLinks: navLinks, errorMessage: "Password can not be empty"});
        return;
    }

    const schema = Joi.object(
    {
            email:  Joi.string().email().required(),
            password: Joi.string().max(30).required()
    });

    const validationResult = schema.validate(req.body);

    if(validationResult.error) {
        res.render("login", {title: 'Log In', navLinks: navLinks, errorMessage: validationResult.error.details[0].message});
        return;
    }

    const result = await userCollection.find({email: email})
                                       .project({name: 1, email: 1, password: 1, _id: 1, userType: 1})
                                       .toArray();

    if (result.length !== 1) {
        return res.render("login", {title: "Log In", navLinks: navLinks, errorMessage: 'User not found'});
    }    
    
    if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		
        req.session.authenticated = true;

        req.session.user = {
            name: result[0].name,
            email: result[0].email,
            userType: result[0].userType
        }

		res.redirect('/members');
	} else {
        res.render("login", {title: "Log In", navLinks: navLinks, errorMessage: 'Incorrect Password'});
	}
});

app.get('/members', (req,res) => {
    if(!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    res.render("members", {title: "Members Area", navLinks: navLinks, name: req.session.user.name});
});

app.get('/admin', async (req,res) => {
    if(!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    if(req.session.user.userType !== 'admin') {
        res.status(403);
        res.render("noaccess", {title: 'NO ACCESS', navLinks: navLinks});
        return;
    }

    const userList = await userCollection.find({}).toArray();
    const currentUser = req.session.user.name;

    res.render("admin", {title: 'Admin', navLinks: navLinks, userList: userList, updatedUser: null, newRole: null});
});

app.post('/changeRole', async (req,res) => {
    if(!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    if(req.session.user.userType !== 'admin') {
        res.status(403);
        res.render("noaccess", {title: 'NO ACCESS', navLinks: navLinks,});
        return;
    }

    const userEmail = req.body.email;
    const newRole = req.body.newRole;

    await userCollection.updateOne({email: userEmail}, {$set: {userType: newRole}});

    const userList = await userCollection.find({}).toArray();

    const updatedUser = await userCollection.findOne({email: userEmail});

    res.render("admin", {title: 'Admin', navLinks: navLinks, userList: userList, updatedUser: updatedUser.name, newRole: newRole});
});

app.get('/logout', (req,res) => {
    req.session.destroy();
    res.render("logout", {title: "Log Out", navLinks: navLinks});
});

app.get("*dummy", (req,res) => {
    res.status(404);
    res.render("404", {title: "404", navLinks: navLinks});
});

app.listen(port, () => {
    console.log('Server running on port ' + port);
});