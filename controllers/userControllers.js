const User = require('../models/userModel');

// Register a user
const registerPOST = async (req, res) => {
	const { name, email, username, password } = req.body;
	try {
		const user = new User({
			name,
			email,
			username,
			password,
		});

		// Save new user to database
		await user.save();

		res.status(201).json({
			success: true,
			message: 'User created successfully',
		});
	} catch (error) {
		let err = {};

		// Handle validation errors
		if (error._message === 'user validation failed') {
			Object.keys(error.errors).forEach((errPath) => {
				err[errPath] = error.errors[errPath].message;
			});
			return res.status(400).json({ err });
		}

		// Handle must-unique props errors
		if (error.code === 11000 && error.keyPattern.email) {
			err.email = 'Email is already registered';
			return res.status(400).json({ err });
		}
		if (error.code === 11000 && error.keyPattern.username) {
			err.username = 'Username is already taken';
			return res.status(400).json({ err });
		}

		// Handle other errors
		res.status(400).json({ err: error });
	}
};

// Login a user
const loginPOST = async (req, res) => {
	const { username, password } = req.body;
	try {
		const user = await User.login(username, password);
		const token = await User.createToken(user);
		res.cookie(process.env.JWT_COOKIE_NAME || 'jwt', token, {
			maxAge: 3600000,
			httpOnly: true,
			secure: process.env.NODE_ENV === 'production' ? true : false,
		});
		res.json({
			success: true,
			message: 'User logged in successfully',
			token,
		});
	} catch (err) {
		res.status(400).json({
			err: true,
			message: err.message,
		});
	}
};

// Logout a user
const logoutGET = (req, res) => {};

// View current logged in user profile
const viewCurrentUserProfileGET = (req, res) => {};

// View specific user profile
const viewSpecificUserProfileGET = async (req, res) => {
	try {
		const user = await User.findOne({ username: req.params.username })
			// Filter user props that will be used in the response
			.select('-role -email -password -createdAt -updatedAt -__v');
		if (!user)
			return res.status(400).json({
				err: true,
				message: 'User does not exist',
			});
		res.json(user);
	} catch (err) {
		res.status(400).json({ err });
	}
};

// View all user profiles
const viewAllUserProfilesGET = async (req, res) => {
	try {
		const users = await User.find()
			// Filter user props that will be used in the response
			.select('-role -email -password -createdAt -updatedAt -__v');
		res.json(users);
	} catch (err) {
		res.status(400).json({ err });
	}
};

// Update current logged in user profile
const updateCurrentUserProfilePATCH = (req, res) => {};

// Change current logged in user password
const changeCurrentUserPasswordPATCH = (req, res) => {};

// Delete current logged in user
const deleteCurrentUserDELETE = (req, res) => {};

module.exports = {
	registerPOST,
	loginPOST,
	logoutGET,
	viewCurrentUserProfileGET,
	viewSpecificUserProfileGET,
	viewAllUserProfilesGET,
	updateCurrentUserProfilePATCH,
	changeCurrentUserPasswordPATCH,
	deleteCurrentUserDELETE,
};
