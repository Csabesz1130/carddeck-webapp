const bcrypt = require('bcrypt');
const { validationResult } = require('express-validator');
const User = require('../models/user');

// Render the login page
const loginGet = (req, res) => {
  res.render('login', { title: 'Login' });
};

// Handle the login request
const loginPost = async (req, res) => {
  // Validate the request body
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).render('login', { title: 'Login', errors: errors.array() });
  }

  // Check if user exists
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(401).render('login', { title: 'Login', errorMessage: 'Invalid email or password' });
  }

  // Check if password is correct
  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).render('login', { title: 'Login', errorMessage: 'Invalid email or password' });
  }

  // Set the session user ID
  req.session.userId = user._id;

  // Redirect to the home page
  res.redirect('/');
};

// Render the registration page
const registerGet = (req, res) => {
  res.render('register', { title: 'Register' });
};

// Handle the registration request
const registerPost = async (req, res) => {
  // Validate the request body
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).render('register', { title: 'Register', errors: errors.array() });
  }

  // Check if user already exists
  const { email, password } = req.body;
  const userExists = await User.exists({ email });
  if (userExists) {
    return res.status(409).render('register', { title: 'Register', errorMessage: 'Email already in use' });
  }

  // Hash the password and create the user
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ email, password: hashedPassword });
  await user.save();

  // Redirect to the login page
  res.redirect('/login');
};

// Handle the logout request
const logout = (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/login');
  });
};

module.exports = {
  loginGet,
  loginPost,
  registerGet,
  registerPost,
  logout,
};
