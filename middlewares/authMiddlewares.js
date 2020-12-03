const expressJwt = require('express-jwt');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = process.env;

// Verify if user is authenticated
const verifyAuth = expressJwt({
	secret: JWT_SECRET || 'ultimateSecret',
	algorithms: ['HS256'],
});

// Don't let user in if already authenticated
const verifyUnauth = (req, res, next) => {
	const token = req.get('Authorization').split(' ')[1];
	if (token)
		return jwt.verify(
			token,
			JWT_SECRET,
			{ algorithms: ['HS256'] },
			(err, decoded) => {
				if (err) return next();
				res.status(400).json({
					err: true,
					message: "You're already logged in",
				});
			}
		);
	next();
};

module.exports = {
	verifyAuth,
	verifyUnauth,
};
