const express = require('express');
const mongoose = require('mongoose');

// Initializations
require('dotenv').config();
const { DB_URI, PORT } = process.env;
const app = express();

// Connect to database
mongoose
	.connect(DB_URI, {
		// Remove deprecation warnings in the console
		useNewUrlParser: true,
		useUnifiedTopology: true,
		useFindAndModify: false,
		useCreateIndex: true,
	})
	.then(() => {
		console.log('Connected to database successfully');

		// Start the server
		app.listen(PORT, (err) => {
			if (err) throw err;
			console.log(`Server is listening on port ${PORT}`);
		});
	})
	.catch((err) => console.log(err));
