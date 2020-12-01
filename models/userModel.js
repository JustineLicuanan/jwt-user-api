const mongoose = require('mongoose');
const { isEmail, isAlphanumeric } = require('validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

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
	try {
		const salt = await bcrypt.genSalt(10);
		this.password = await bcrypt.hash(this.password, salt);
		next();
	} catch (err) {
		next(err);
	}
});

// Static method to login user
User.statics.login = async function (username, password) {
	try {
		const user = await this.findOne({ username })
			// Filter user props that will be used in the response
			.select('-__v');
		if (!user) throw new Error('Username is incorrect');
		const isMatch = await bcrypt.compare(password, user.password);
		if (!isMatch) throw new Error('Password is incorrect');
		return user;
	} catch (err) {
		throw err;
	}
};

// Static method to create token
User.statics.createToken = function ({
	_id,
	role,
	name,
	email,
	username,
	createdAt,
	updatedAt,
}) {
	return jwt.sign(
		{
			_id,
			role,
			name,
			email,
			username,
			createdAt,
			updatedAt,
		},
		process.env.JWT_SECRET || 'ultimateSecret',
		{ expiresIn: '1h' }
	);
};

module.exports = mongoose.model('user', User);
