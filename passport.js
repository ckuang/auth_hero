// load all the things we need
var LocalStrategy = require('passport-local').Strategy;

// load up the user model
var User = require('./models').User;
var bcrypt = require('bcrypt-nodejs')

module.exports = function(passport) {

    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        User.findById(id).then(function(user){
          done(null, user)
        }).catch(function(err){
          done(err, null)
        })
    });

    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
    passport.use('local-login', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
    function(req, email, password, done) {
        if (email) {
          email = email.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching
        }

        // asynchronous
        process.nextTick(function() {
            User.findOne({'email': email })
              .then(function(user) {
                // if no user is found, return the message
                user = user.dataValues
                if (!user) {
                  return done(null, false, req.flash('loginMessage', 'No user found.'));
                }

                if (!bcrypt.compareSync(password, user.password)) {
                  return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.'));
                }

                // all is well, return user
                else {
                  return done(null, user);
                }
              })
              .catch(function(err){
                // if there are any errors, return the error
                return done(err);
              });
        });

    }));

    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    passport.use('local-signup', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
    function(req, email, password, done) {
        if (email) {
          email = email.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching
        }

        // asynchronous
        process.nextTick(function() {
            // if the user is not already logged in:
            if (!req.user) {
                User.findOne({'email': email})
                  .then(function(user){
                    user = user.dataValues
                    if (user) {
                        return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
                    } else {

                           // create the user
                           User.create({
                             'email': email,
                             'password': User.generateHash(password)
                           })
                           .then(function(user){
                             return done(null, user)
                           })
                           .catch(function(err) {
                             return done(err)
                           })

                    }
                  })
                  .catch(function(err){
                    return done(err)
                  })
          }
        })


    }));
}
