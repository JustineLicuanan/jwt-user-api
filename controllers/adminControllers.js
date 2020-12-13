const User = require('../models/userModel');

// Create a user
const createUserPOST = async (req, res) => {
	const { role, name, email, username, password } = req.body;
	try {
		const user = new User({
			role,
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

// View specific user profile
const viewSpecificUserProfileGET = async (req, res) => {
	try {
		const user = await User.findOne({ username: req.params.username })
			// Filter user props that will be used in the response
			.select('-password -__v');
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
			.select('-password -__v');
		res.json(users);
	} catch (err) {
		res.status(400).json({ err });
	}
};

// Update specific user profile
const updateSpecificUserProfilePATCH = (req, res) => {};

// Change specific user password
const changeSpecificUserPasswordPATCH = (req, res) => {};

// Delete specific user
const deleteSpecificUserDELETE = (req, res) => {};

module.exports = {
	createUserPOST,
	viewSpecificUserProfileGET,
	viewAllUserProfilesGET,
	updateSpecificUserProfilePATCH,
	changeSpecificUserPasswordPATCH,
	deleteSpecificUserDELETE,
};
