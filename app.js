var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var bcrypt = require('bcryptjs');


const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

require("dotenv").config();

const mongoDb = `mongodb+srv://inventory-admin:${process.env.SECRET_KEY}@cluster0.ynqmqjk.mongodb.net/auth?retryWrites=true&w=majority`;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  })
);

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.use('/', indexRouter);
app.use('/users', usersRouter);

// Set up Passport's LocalStrategy for user authentication
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      // Find the user with the provided username
      const user = await User.findOne({ username: username });
      // If the user is not found, return with a message
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }

      // Compare the provided password with the stored hashed password
      bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          // If the passwords match, log the user in
          return done(null, user);
        } else {
          // If the passwords do not match, return with a message
          return done(null, false, { message: "Incorrect password" });
        }
      });
    } catch (err) {
      return done(err);
    }
  })
);

// Serialize the user for session storage
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

// Deserialize the user from session storage
passport.deserializeUser(async function (id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Middleware to make the current user available in views
app.use(function (req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

// Route for rendering the sign-up form
app.get("/sign-up", (req, res) => res.render("sign-up-form", { title: "Sign up" }));

// Route for handling user sign-up
app.post("/sign-up", async (req, res, next) => {
  try {
    // Create a new user with the provided username and password
    const user = new User({
      username: req.body.username,
      password: req.body.password,
    });

    // Hash the user's password before saving it to the database
    bcrypt.hash(user.password, 10, async (err, hashedPassword) => {
      user.password = hashedPassword;
      try {
        // Save the user to the database
        const result = await user.save();
        // Redirect to the homepage
        res.redirect("/");
      } catch (err) {
        return next(err);
      }
    });
  } catch (err) {
    return next(err);
  }
});

// Route for handling user log-in
app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

// Route for handling user log-out
app.get("/log-out", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
