const express = require('express');
const connectDB = require('./database/db');
const userRoutes = require('./routes/userRoutes');
require('dotenv').config();
const passport = require('./middleware/passport');

const app = express();
const PORT = process.env.PORT || 8000;

app.use(express.json());
app.use(passport.initialize());

// Routes
app.use('/user', userRoutes);

connectDB();

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});