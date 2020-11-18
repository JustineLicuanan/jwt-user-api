// Register a user
const registerPOST = (req, res) => {};

// Login a user
const loginPOST = (req, res) => {};

// Logout a user
const logoutGET = (req, res) => {};

// View current logged in user profile
const viewCurrentUserProfileGET = (req, res) => {};

// View specific user profile
const viewSpecificUserProfileGET = (req, res) => {};

// View all user profiles
const viewAllUserProfilesGET = (req, res) => {};

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
