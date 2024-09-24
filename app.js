// app.js
const express = require('express');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to the database
require('./config/db').connect();

// Middleware :
app.use(express.json());

// Routes :

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});