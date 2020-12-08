const express = require('express');
const {
	createUserPOST,
	viewSpecificUserProfileGET,
	viewAllUserProfilesGET,
	updateSpecificUserProfilePATCH,
	changeSpecificUserPasswordPATCH,
	deleteSpecificUserDELETE,
} = require('../controllers/adminControllers');

// Initializations
const router = express.Router();

// Routes
router.post('/create', createUserPOST);
router.get('/view/:username', viewSpecificUserProfileGET);
router.get('/view', viewAllUserProfilesGET);
router.patch('/update/:username', updateSpecificUserProfilePATCH);
router.patch('/update/password/:username', changeSpecificUserPasswordPATCH);
router.delete('/delete/:username', deleteSpecificUserDELETE);

module.exports = router;
