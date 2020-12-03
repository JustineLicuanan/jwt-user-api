const express = require('express');
const jwt = require('express-jwt');
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

// Initializations
const { JWT_SECRET } = process.env;
const router = express.Router();

// Middlewares
router.use(
	jwt({
		secret: JWT_SECRET || 'ultimateSecret',
		algorithms: ['HS256'],
	}).unless({
		path: [
			'/users/register',
			'/users/login',
			'/users/profile/:username',
			'/users',
		],
	})
);

// Routes
router.post('/register', registerPOST);
router.post('/login', loginPOST);
router.get('/logout', logoutGET);
router.get('/profile', viewCurrentUserTokenGET);
router.get('/profile/:username', viewSpecificUserProfileGET);
router.get('/', viewAllUserProfilesGET);
router.patch('/profile/update', updateCurrentUserProfilePATCH);
router.patch('/profile/update/password', changeCurrentUserPasswordPATCH);
router.delete('/profile/delete', deleteCurrentUserDELETE);

module.exports = router;
