const express = require('express');
const router = new express.Router();
const ExpressError = require('../expressError');
const jwt = require('jsonwebtoken');
const { SECRET_KEY } = require('../config');

const User = require('../models/user');

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post('/login', async function (req, res, next) {
    try {
        const { username, password } = req.body;
        let result = await User.authenticate(username, password);

        if (result === true) {
            await User.updateLoginTimestamp(username);
            const token = jwt.sign({ username }, SECRET_KEY);
            return res.json({ message: `Logged in!`, token });
        }
        throw new ExpressError('Invalid username/password', 400);
    } catch (err) {
        return next(err);
    }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post('/register', async function (req, res, next) {
    try {
        const { username, password, first_name, last_name, phone } = req.body;
        let result = await User.register({
            username,
            password,
            first_name,
            last_name,
            phone,
        });

        if (result) {
            await User.authenticate(username, password);
            return res.json({
                message: `Successfully registered!`,
                user: result,
            });
        }
        throw new ExpressError('Invalid username/password', 400);
    } catch (err) {
        return next(err);
    }
});

module.exports = router;
