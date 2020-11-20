const mongoose = require('mongoose');
const { isEmail, isAlphanumeric } = require('validator');
const bcrypt = require('bcryptjs');

// Initializations
const Schema = mongoose.Schema;

// Create user schema
const User = new Schema(
	{
		role: {
			type: Number,
			default: 4,
		},
		name: {
			type: String,
			trim: true,
			required: [true, 'Name field is required'],
		},
		email: {
			type: String,
			lowercase: true,
			validate: [isEmail, 'Email must be valid'],
			unique: true,
			required: [true, 'Email field is required'],
		},
		username: {
			type: String,
			minlength: [6, 'Username must be 6-26 characters long'],
			maxlength: [26, 'Username must be 6-26 characters long'],
			lowercase: true,
			validate: [
				isAlphanumeric,
				'Username must only contain letters and numbers',
			],
			unique: true,
			required: [true, 'Username field is required'],
		},
		password: {
			type: String,
			minlength: [8, 'Password must be atleast 8 characters long'],
			required: [true, 'Password field is required'],
		},
	},
	{ timestamps: true }
);

// Hash password before saving to database
User.pre('save', async function (next) {
	const salt = await bcrypt.genSalt(10);
	this.password = await bcrypt.hash(this.password, salt);
	next();
});

module.exports = mongoose.model('user', User);
