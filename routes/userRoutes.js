const express = require('express');
const {
	registerPOST,
	loginPOST,
	logoutGET,
	viewCurrentUserProfileGET,
	viewSpecificUserProfileGET,
	viewAllUserProfilesGET,
	updateCurrentUserProfilePATCH,
	changeCurrentUserPasswordPATCH,
	deleteCurrentUserDELETE,
} = require('../controllers/userControllers');

// Initializations
const router = express.Router();

// Routes
router.post('/register', registerPOST);
router.post('/login', loginPOST);
router.get('/logout', logoutGET);
router.get('/profile', viewCurrentUserProfileGET);
router.get('/profile/:username', viewSpecificUserProfileGET);
router.get('/', viewAllUserProfilesGET);
router.patch('/profile/update', updateCurrentUserProfilePATCH);
router.patch('/profile/update/password', changeCurrentUserPasswordPATCH);
router.delete('/profile/delete', deleteCurrentUserDELETE);

module.exports = router;
