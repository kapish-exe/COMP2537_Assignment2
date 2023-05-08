require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");
const { name } = require("ejs");


const expireTime = 60 * 60 * 1000; 
var checklogin = false;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})


app.use(express.static(__dirname + "/public"));


app.use(session({
    secret: node_session_secret,
    store: mongoStore, 
    saveUninitialized: false,
    resave: true
}
));

app.set('view engine', 'ejs')

app.get('/', (req, res) => {
    if (checklogin) {
        res.redirect("/members")
    } else {

        res.render('landing')
    }
});

app.get("/signup", (req, res) => {

    res.render('signup')
})


app.get('/about', (req, res) => {
    var color = req.query.color;
    res.render('about', {color: color});
});

app.get('/miss', (req, res) => {
    var missingfields = req.query.missing;

    res.render('missing', {missingfields: missingfields})
});

app.get('/login', (req, res) => {

    res.render('login')
});

app.post('/submitUser', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;
    var newsession = req.session;
    req.session.name = name;
    const schema = Joi.object(
        {
            name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/signup");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
         name: name, 
         email: email, 
         password: hashedPassword, 
         userType: "user" });

    console.log("Inserted user");

    res.redirect("/members");
});


app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().email().required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ email: 1, password: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {

        res.render('incorrectpass')
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.cookie.maxAge = expireTime;
        var user = await userCollection.findOne({ email });
        req.session.name = user.name;
        req.session.user = user;


        checklogin = true;
        res.redirect('/members');
        return;
    }
    else {
        res.render('incorrectpass')
        return;
    }
});

app.get('/loggedin', async (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    console.log(req.session.name)
    res.render('loggedin', {uname: req.session.name})

});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.render('logout')
});

app.get('/admin', async (req, res) => {
    if (!req.session.authenticated) {
        console.log("User not logged, redirecting to login page");
        res.redirect("/login");
        return;
      }
      if (req.session.user.userType !== "admin") {
        console.log("User not admin, redirecting to members page");
        res.render("errorpage");
        return;
      }
    
      const users = await userCollection.find({}).toArray();
    
      res.render("admin", { user: req.session.user, users });
})

app.post("/admin/promote", async (req, res) => {
    const { usernameToPromote } = req.body;
    const result = await userCollection.updateOne(
      { email: usernameToPromote },
      { $set: { userType: "admin" } }
    );
    if (result.matchedCount === 0) {
      console.log("Error promoting user");
      const error = 1;
      const users = await userCollection.find({}).toArray();
      res.render("admin", { user: req.session.user, users, error });
      return;
    } else {
      console.log("User promoted");
      res.redirect("/admin");
      return;
    }
  });

  app.post("/admin/demote", async (req, res) => {
    const { usernameToDemote } = req.body;
    const result = await userCollection.updateOne(
      { email: usernameToDemote },
      { $set: { userType: "user" } }
    );
    if (result.matchedCount === 0) {
      console.log("Error demoting user");
      const users = await userCollection.find({}).toArray();
      const error = 2;
      res.render("admin", { user: req.session.user, users, error });
      return;
    } else {
      console.log("User demoted");
      res.redirect("/admin");
      return;
    }
  });

app.get("/members", (req, res) => {
    if(req.session.authenticated){
        res.render('members', {name: req.session.name} )    
        return
    }
    else{
        res.redirect('/login')
        return
    }
})

app.get("*", (req, res) => {
    res.status(404);
    res.render('404');
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 