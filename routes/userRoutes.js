const express = require('express');
const {
	registerPOST,
	loginPOST,
	logoutGET,
	viewCurrentUserTokenGET,
	viewSpecificUserProfileGET,
	viewAllUserProfilesGET,
	updateCurrentUserProfilePATCH,
	changeCurrentUserPasswordPATCH,
	deleteCurrentUserDELETE,
} = require('../controllers/userControllers');
const { verifyAuth, verifyUnauth } = require('../middlewares/authMiddlewares');

// Initializations
const router = express.Router();

// Routes
router.post('/register', verifyUnauth, registerPOST);
router.post('/login', verifyUnauth, loginPOST);
router.get('/logout', verifyAuth, logoutGET);
router.get('/profile', verifyAuth, viewCurrentUserTokenGET);
router.get('/profile/:username', viewSpecificUserProfileGET);
router.get('/', viewAllUserProfilesGET);
router.patch('/profile/update', verifyAuth, updateCurrentUserProfilePATCH);
router.patch(
	'/profile/update/password',
	verifyAuth,
	changeCurrentUserPasswordPATCH
);
router.delete('/profile/delete', verifyAuth, deleteCurrentUserDELETE);

module.exports = router;
