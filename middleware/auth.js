const jwt = require('jsonwebtoken');
const config = require('config');


// next is a callback to move to next middleware
module.exports = function(req, res, next){
	// Get token from header
	const token = req.header('x-auth-token');

	// Check id no token
	if(!token){
		return res.status(401).json({ msg: 'No token, authorisation denied !!!' });
	}


	// Verify the token
	try{
		const decoded = jwt.verify(token, config.get('jwtSecret'));

		req.user = decoded.user;
		next();
	}catch(err){
		res.status(401).json({ msg: 'Token is not valid' });
	}

}	