require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
/* secret for the cookie session */
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

app.set('view engine', 'ejs');
app.use('/img', express.static('./public/'));
app.use(express.urlencoded({ extended: false }));

// Gets a reference to the mongo database / creates a mongo client
const MongoClient = require("mongodb").MongoClient;
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true`;
let database = new MongoClient(atlasURI, { useNewUrlParser: true, useUnifiedTopology: true });

const usersCollection = database.db(mongodb_database).collection('users');

const mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/Comp2537Assignment1`,
    crypto: {
      secret: mongodb_session_secret
    }
  });

// Generates the cookie
const createSession = (req) => {
    req.session.authenticated = true;
    req.session.name = req.body.name;
    req.session.email = req.body.email;
    req.session.cookie.maxAge = expireTime;
  };

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
  }));

  function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
  if (req.session.user_type == 'admin') {
      return true;
  }
  return false;
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
      res.status(403);
      res.render("errorMessage", {error: "Not Authorized"});
      return;
  }
  else {
      next();
  }
}

app.get('/', async (req, res) => {
    res.render('index', {req: req, active: 'home'});
  });
  
  // Login page
  app.get('/login', (req, res) => {
    res.render('login');
  });
  
  app.post('/loggingin', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
  
    const schema = Joi.object(
      {
        email: Joi.string().email(),
        password: Joi.string().max(20).required()
      }
    );
  
    const validationResult = schema.validate(req.body);
    if (validationResult.error != null) {
      res.redirect("/invalidLogin");
      return;
    }
  
    const result = await usersCollection.find({ email: email }).project({ email: 1, name: 1, password: 1 }).toArray();
  
    if (result.length != 1) {
      res.redirect('/invalidLogin');
      return;
    }
  
    const passwordOk = await bcrypt.compare(password, result[0].password)
    if (passwordOk) {
      req.body.name = result[0].name;
      createSession(req);
      res.redirect('/members');
    }
    else {
      res.redirect("/invalidLogin");
    }
  });
  
  app.get('/invalidLogin', (req, res) => {
    res.render('invalidLogin');
  });
  
  app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
  });
  
  // New user signup page
  app.get('/signup', (req, res) => {
    res.render('signup');
  });
  
  app.post('/signupSubmit', async (req, res) => {
  
    const email = req.body.email;
    const name = req.body.name;
    const password = req.body.password;
  
    const schema = Joi.object(
      {
        name: Joi.string().alphanum().max(20).required(),
        password: Joi.string().max(20).required(),
        email: Joi.string().email().required()
      }
    );
  
    const validationResult = schema.validate(req.body);
  
    let html;
    let emails = await usersCollection.find({ email: email }).project({ email: 1 }).toArray();
  
    if (validationResult.error != null) {
  
      html = `
        <h1>${validationResult.error.details[0].message}</h1>
        <a href="/signup">Try again</a>
        `;
      res.send(html);
  
    } else if (emails.length == 0) {
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      await usersCollection.insertOne({ email: email, name: name, password: hashedPassword });
      createSession(req);
      res.redirect('/members');
    } else {
      html = `
          <h1>Sorry, that email is already used</h1>
          <a href="/signup">Try again</a>
          `;
      res.send(html);
    }
  });
  
  //As per demo, not yet fully functional, members.ejs has been excluded at this time.
  app.get('/members/:id', (req, res) => {
    var members = req.params.id;

    res.render("members", {members: members});
  });
  
  app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({username: 1, _id: 1}).toArray();
 
    res.render("admin", {users: result});
});

  app.get("*", (req,res) => {
    res.status(404);
    res.render("404");
  })
  
  app.listen(port, () => console.log(`Listening on port ${port}...`));