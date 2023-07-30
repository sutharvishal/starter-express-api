const express = require('express');
const { handleSignIn, handleRedirect, handleSignOut, acquireToken, handleRefreshTokenRequest } = require('../controllers/auth/MicrosoftOauthController');
const router = express.Router();

router.get('/signin', handleSignIn);

router.get('/acquireToken', acquireToken);

router.post('/redirect', handleRedirect);

router.post('/refreshToken', handleRefreshTokenRequest);

router.get('/signout', handleSignOut);

module.exports = router;