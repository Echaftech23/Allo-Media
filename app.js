const express = require('express');
const session = require('express-session');
const authRoutes = require('./routes/authRoutes');
require('dotenv').config();
// const userRoutes = require('./routes/userRoutes');
// const deliveryRoutes = require('./routes/deliveryRoutes');
// const managerRoutes = require('./routes/managerRoutes');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to the database
require('./config/db').connect();

// Middleware :
app.use(express.json());

// Configure session middleware
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } 
}));

// Routes :
app.use('/auth', authRoutes);
// app.use('/user', userRoutes);
// app.use('/delivery', deliveryRoutes);
// app.use('/manager', managerRoutes);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});