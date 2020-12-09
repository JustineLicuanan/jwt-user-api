const express = require('express');
const {
	createUserPOST,
	viewSpecificUserProfileGET,
	viewAllUserProfilesGET,
	updateSpecificUserProfilePATCH,
	changeSpecificUserPasswordPATCH,
	deleteSpecificUserDELETE,
} = require('../controllers/adminControllers');
const { verifyAuth, verifyAdmin } = require('../middlewares/authMiddlewares');

// Initializations
const router = express.Router();

// Routes
router.post('/create', verifyAuth, verifyAdmin, createUserPOST);
router.get(
	'/view/:username',
	verifyAuth,
	verifyAdmin,
	viewSpecificUserProfileGET
);
router.get('/view', verifyAuth, verifyAdmin, viewAllUserProfilesGET);
router.patch(
	'/update/:username',
	verifyAuth,
	verifyAdmin,
	updateSpecificUserProfilePATCH
);
router.patch(
	'/update/password/:username',
	verifyAuth,
	verifyAdmin,
	changeSpecificUserPasswordPATCH
);
router.delete(
	'/delete/:username',
	verifyAuth,
	verifyAdmin,
	deleteSpecificUserDELETE
);

module.exports = router;
