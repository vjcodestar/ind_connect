const express = require('express');
const router = express.Router();

const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');

const jwt = require('jsonwebtoken');

const config = require('config'); 

const { check, validationResult } = require('express-validator/check');

const User = require('../../models/User');
// @route    GET api/users
// @desc     Register User
// @access   Public
router.post('/', 
	[
		check('name', 'Name is required')
		.not()
		.isEmpty(),
		check('email', 'Please include a valid email').isEmail(),
		check('password', 'Please enter password with 6 or more character').isLength({ min: 6})
	], 
	async(req, res) => {
		// console.log(req.body);
		const errors = validationResult(req);
		if(!errors.isEmpty()){
			return res.status(400).json({ errors: errors.array()}); // Bad Request 
		}

		const { name, email, password } = req.body;

		try{
			// See if the user exists
			let user = await User.findOne({ email: email });

			if(user){
				return res
				.status(400)
				.json({ errors: [{ msg: 'User already exists!' }] });
			}

			// Get users gravatar
			const avatar = gravatar.url(email, {
				s: '200', // size
				r: 'pg', // rating * adult content
				d: 'mm' // default i.e default image
			});

			// Creates an instance
			user = new User({
				name,
				email,
				avatar,
				password
			});

			// Encrypt password
			// Note : anything with promise use await
			const salt = await bcrypt.genSalt(10);

			user.password = await bcrypt.hash(password, salt);

			await user.save();

			// Return jsonwebtoken
			const payload = { // data
				user: {
					id: user.id // or user._id as mongoose has an abstraction layer we can use user.id as well
				}
			}

			jwt.sign(
				payload, 
				config.get('jwtSecret'),
				{ expiresIn: 360000 }, (err, token) => {
					if(err) throw err;
					res.json({ token })
				}
			);


		} catch(err){
			console.error(err.message);
			res.status(500).send('Server Error');
		}

});

module.exports = router;