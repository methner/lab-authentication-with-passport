const express = require('express');
const router = express.Router();
// Require user model
const User = require('../models/User.model');
// Add bcrypt to encrypt passwords
const bcrypt = require('bcryptjs');
// Add passport
const passport = require('passport');

const ensureLogin = require('connect-ensure-login');

router.get('/private-page', ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render('passport/auth/private', { user: req.user });
});

router.get('auth/signup', (req, res) => {
  res.render('auth/signup');
});

router.get('auth/login', (req, res) => {
  res.render('auth/login');
});


router.post('auth/signup', (req, res, next) => {
  const { username, password } = req.body;
  if (password.length < 8) {
    res.render('auth/signup', {
      message: 'Your password must be 8 characters minimun.'
    });
    return;
  }
  if (username === '') {
    res.render('auth/signup', { message: 'Your username cannot be empty' });
    return;
  }
  User.findOne({ username: username }).then(found => {
    if (found !== null) {
      res.render('auth/signup', { message: 'This username is already taken' });
    } else {
      // we can create a user with the username and password pair
      const salt = bcrypt.genSaltSync();
      const hash = bcrypt.hashSync(password, salt);

      User.create({ username: username, password: hash })
        .then(dbUser => {
          // login with passport 
          req.login(dbUser, err => {
            if (err) {
              next(err);
            } else {
              res.redirect('/');
            }
          })
        })
        .catch(err => {
          next(err);
        });
    }
  });
});


router.post(
  'auth/login',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: 'auth/login',
    passReqToCallback: true
  })
);

module.exports = router;
