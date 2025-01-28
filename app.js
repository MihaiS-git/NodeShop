const path = require('path');
const fs = require('fs');
const https = require('https');

const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const csrf = require('csurf');
const flash = require('connect-flash');
const multer = require('multer');
const dotenv = require('dotenv').config();
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');

const errorController = require('./controllers/error');
const User = require('./models/user');

console.log(process.env.NODE_ENV);


// db connection string
const MONGODB_URI = process.env.MONGODB_URI;

// create express app
const app = express();
// session store
const store = new MongoDBStore({
  uri: MONGODB_URI,
  collection: 'sessions'
});
// csrf protection
const csrfProtection = csrf();

/* const privateKey = fs.readFileSync('server.key');
const certificate = fs.readFileSync('server.cert'); */

// for file upload - rename the file...
const fileStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const destPath = path.join(__dirname, 'images');
    console.log('Destination Path:', destPath);
    cb(null, destPath);
  },
  filename: (req, file, cb) => {
    const timestamp = new Date().toISOString().replace(/:/g, '-');
    const filename = `${timestamp}-${file.originalname}`;
    console.log('Filename:', filename);
    cb(null, filename);
  }
});

const fileFilter = (req, file, cb) => {
  if (
    file.mimetype === 'image/png' ||
    file.mimetype === 'image/jpg' ||
    file.mimetype === 'image/jpeg'
  ) {
    cb(null, true);
  } else {
    cb(null, false);
  }
};

// view engine configuration
app.set('view engine', 'ejs');
app.set('views', 'views');

// routes configuration
const adminRoutes = require('./routes/admin');
const shopRoutes = require('./routes/shop');
const authRoutes = require('./routes/auth');

const accessLogStream = fs.createWriteStream(
  path.join(__dirname, 'access.log'),
  { flags: 'a' }
);

app.use(helmet());
app.use(compression());
app.use(morgan('combined', {stream: accessLogStream}));

// middleware for parsing request body
app.use(bodyParser.urlencoded({ extended: false }));
// middleware for parsing request body - files | 'image' is the fieldname in the view
app.use(multer({storage: fileStorage, fileFilter: fileFilter}).single('image'));
// middleware for serving static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'images')));
// middleware for session management
app.use(
  session({
    secret: 'my secret',
    resave: false,
    saveUninitialized: false,
    store: store
  })
);
app.use(csrfProtection);
app.use(flash());

// middleware for setting up csrf token and isAuthenticated to be available in all views
app.use((req, res, next) => {
  res.locals.isAuthenticated = req.session.isLoggedIn;
  res.locals.csrfToken = req.csrfToken();
  next();
});

// middleware for setting up user in the request
app.use((req, res, next) => {
  if (!req.session.user) {
    return next();
  }
  User.findById(req.session.user._id)
    .then(user => {
      if (!user) {
        return next();
      }
      req.user = user;
      next();
    })
    .catch(err => {
      // must use next instead of throw in async code
      next(new Error(err));
    });
});

// setting routes
app.use('/admin', adminRoutes);
app.use(shopRoutes);
app.use(authRoutes);

// error handling
app.get('/500', errorController.get500);

app.use(errorController.get404);

app.use((error, req, res, next) => {
  // res.status(error.httpStatusCode).render(...);
  // res.redirect('/500');
  console.log(error);
  res.status(500).render('500', {
    pageTitle: 'Error!',
    path: '/500',
    isAuthenticated: req.session.isLoggedIn
  });
});

// connect to db and start server
mongoose
  .connect(MONGODB_URI)
  .then(result => {
/*     https
      .createServer({ key: privateKey, cert: certificate }, app)
      .listen(process.env.PORT || 3000); */
    app.listen(process.env.PORT || 3000);
  })
  .catch(err => {
    console.log(err);
  });