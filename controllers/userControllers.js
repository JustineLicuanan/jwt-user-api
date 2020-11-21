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
const loginPOST = (req, res) => {};

// Logout a user
const logoutGET = (req, res) => {};

// View current logged in user profile
const viewCurrentUserProfileGET = (req, res) => {};

// View specific user profile
const viewSpecificUserProfileGET = (req, res) => {};

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
