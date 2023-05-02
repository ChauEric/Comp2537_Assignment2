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


app.use(express.urlencoded({ extended: false }));

// Generates the cookie
const createSession = (req) => {
    req.session.authenticated = true;
    req.session.name = req.body.name;
    req.session.email = req.body.email;
    req.session.cookie.maxAge = expireTime;
  };

app.use('/img', express.static('./public/'));

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
  }));

app.get('/', async (req, res) => {

    let html = `
      <h1>Welcome to this page</h1>
      <a href="/login">Login</a>
      <br>
      <br>
      <a href="/signup">Signup</a>
      `;
  
    if (req.session.authenticated) {
      html = `
        <h1>Welcome, ${req.session.name}</h1>
        <a href="/members">Member's Only Zone</a>
        <br>
        <br>
        <a href="/logout">Signout</a>
        `;
    }
  
    res.send(html);
  });
  
  // Login page
  app.get('/login', (req, res) => {
    let html = `
      <h1>Sign In</h1>
      <form action="/loggingin" method="post">
        <input type="text" name="email" placeholder="email">
        <input type="password" name="password" placeholder="password">
        <button>Submit</button>
      </form>
    <br>
    <p>or</p>
    <br>
    <a href="/signup">Signup</a>`;
    res.send(html);
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
    let html = `
      <h1>Invalid password</h1>
      <a href="/login">Try again</a>
    `;
    res.send(html);
  });
  
  app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
  });
  
  // New user signup page
  app.get('/signup', (req, res) => {
    let html = `
      <h1>Signup</h1>
      <form action="/signupSubmit" method="post">
        <input type="text" name="name" placeholder="name">
        <input type="password" name="password" placeholder="password">
        <input type="text" name="email" placeholder="email">
        <button>Submit</button>
      </form>
    <br>
    <p>or</p>
    <br>
    <a href="/login">Login</a>`;
    res.send(html);
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
  
  app.get('/members', (req, res) => {
  
    const images = [
      {
        image: 'Homer.webp',
        caption: '... well I best be going'
      },
      {
        image: 'NyanCat.webp',
        caption: 'remember this meme?'
      },
      {
        image: 'clapping-shia.gif',
        caption: 'we are so happy to see you'
      }
    ];
  
    if (req.session.authenticated) {
      let image = images[Math.floor(Math.random() * images.length)];
      let html = `
        <img src="img/${image.image}" alt="image">
        <h1>Hello ${req.session.name}, ${image.caption}</h1>
        <a href="/logout">Signout</a>
        <br>
        <br>
        <a href="/">Home</a>
      `;
      res.send(html);
    } else {
      res.redirect('/');
    }
  });
  
  app.use('*', (req, res) => {
    let html = `
      <h1>404</h1>
      <p>Page not found.</p>
      <br>
      <a href="/">Home</a>
    `;
    res.status(404);
    res.send(html);
  });
  
  app.listen(port, () => console.log(`Listening on port ${port}...`));