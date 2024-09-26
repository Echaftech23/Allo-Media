const express = require('express');
const authRoutes = require('./routes/authRoutes');
// const userRoutes = require('./routes/userRoutes');
// const deliveryRoutes = require('./routes/deliveryRoutes');
// const managerRoutes = require('./routes/managerRoutes');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to the database
require('./config/db').connect();

// Middleware :
app.use(express.json());

// Routes :
app.use('/auth', authRoutes);
// app.use('/user', userRoutes);
// app.use('/delivery', deliveryRoutes);
// app.use('/manager', managerRoutes);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});