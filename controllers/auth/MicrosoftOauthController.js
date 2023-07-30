var msal = require('@azure/msal-node');
var { getUserProfileDetails } = require('../../helpers/MicrosoftGraphHelper');
var { saveAccessToken, findAccessTokenByUserId, updateAccessToken } = require('../../models/accessToken');
var { findUserByEmail } = require('../../models/user');
const {toUTCDate} = require("../../helpers/commonHelper");

const scopes = ["email", "Calendars.Read", "Calendars.ReadBasic", "email", "offline_access", "Contacts.Read"];

var {
    msalConfig,
    REDIRECT_URI,
    POST_LOGOUT_REDIRECT_URI
} = require('../../config/microsoftAuthConfig');

const msalInstance = new msal.ConfidentialClientApplication(msalConfig);
const cryptoProvider = new msal.CryptoProvider();

/**
 * Handles the sign in request from the Addin
 */
const handleSignIn = async (req, res, next) => {

    // create a GUID for crsf
    req.session.csrfToken = cryptoProvider.createNewGuid();

    /**
     * The MSAL Node library allows you to pass your custom state as state parameter in the Request object.
     * The state parameter can also be used to encode information of the app's state before redirect.
     * You can pass the user's state in the app, such as the page or view they were on, as input to this parameter.
     */
    const redirectUrl = req.query.redirect_url;
    // console.log("redirect_url", redirectUrl);
    const state = cryptoProvider.base64Encode(
        JSON.stringify({
            csrfToken: req.session.csrfToken,
            redirectTo: redirectUrl || '/',
        })
    );

    const authCodeUrlRequestParams = {
        state: state,

        /**
         * By default, MSAL Node will add OIDC scopes to the auth code url request. For more information, visit:
         * https://docs.microsoft.com/azure/active-directory/develop/v2-permissions-and-consent#openid-connect-scopes
         */
        scopes: scopes,
    };

    const authCodeRequestParams = {

        /**
         * By default, MSAL Node will add OIDC scopes to the auth code request. For more information, visit:
         * https://docs.microsoft.com/azure/active-directory/develop/v2-permissions-and-consent#openid-connect-scopes
         */
        scopes: [],
    };

    // trigger the first leg of auth code flow
    return redirectToAuthCodeUrl(req, res, next, authCodeUrlRequestParams, authCodeRequestParams)
}

/**
 * Prepares the auth code request parameters and initiates the first leg of auth code flow
 * @param req: Express request object
 * @param res: Express response object
 * @param next: Express next function
 * @param authCodeUrlRequestParams: parameters for requesting an auth code url
 * @param authCodeRequestParams: parameters for requesting tokens using auth code
 */
const redirectToAuthCodeUrl = async (req, res, next, authCodeUrlRequestParams, authCodeRequestParams) => {

    // Generate PKCE Codes before starting the authorization flow
    const { verifier, challenge } = await cryptoProvider.generatePkceCodes();

    // Set generated PKCE codes and method as session vars
    req.session.pkceCodes = {
        challengeMethod: 'S256',
        verifier: verifier,
        challenge: challenge,
    };

    /**
     * By manipulating the request objects below before each request, we can obtain
     * auth artifacts with desired claims. For more information, visit:
     * https://azuread.github.io/microsoft-authentication-library-for-js/ref/modules/_azure_msal_node.html#authorizationurlrequest
     * https://azuread.github.io/microsoft-authentication-library-for-js/ref/modules/_azure_msal_node.html#authorizationcoderequest
     **/

    req.session.authCodeUrlRequest = {
        redirectUri: REDIRECT_URI,
        responseMode: 'form_post', // recommended for confidential clients
        codeChallenge: req.session.pkceCodes.challenge,
        codeChallengeMethod: req.session.pkceCodes.challengeMethod,
        ...authCodeUrlRequestParams,
    };

    req.session.authCodeRequest = {
        redirectUri: REDIRECT_URI,
        code: "",
        ...authCodeRequestParams,
    };

    // Get url to sign user in and consent to scopes needed for application
    try {
        const authCodeUrlResponse = await msalInstance.getAuthCodeUrl(req.session.authCodeUrlRequest);
        res.redirect(authCodeUrlResponse);
    } catch (error) {
        next(error);
    }
}

const handleRedirect = async (req, res, next) => {
    // sdfdsfs
    if (req.body.state) {
        const state = JSON.parse(cryptoProvider.base64Decode(req.body.state));

        console.log("Match Token", state.csrfToken, req.session.csrfToken, req.session);

        // check if csrfToken matches
        if (state.csrfToken === req.session.csrfToken) {
            try {
                req.session.authCodeRequest.code = req.body.code; // authZ code
                req.session.authCodeRequest.codeVerifier = req.session.pkceCodes.verifier // PKCE Code Verifier

                const tokenResponse = await msalInstance.acquireTokenByCode(req.session.authCodeRequest);
                console.log("tokenResponse", tokenResponse)

                console.log("Refresh Token", refreshToken());

                if(typeof tokenResponse.accessToken !== "undefined" && tokenResponse.accessToken) {
                    // set the user as authenticated
                    req.user = {
                        isLoggedIn: true,
                        accessToken: tokenResponse.accessToken
                    };

                    // get current user details from MS Graph API
                    const graphUserDetails = await getUserProfileDetails(req.user.accessToken);

                    if(typeof graphUserDetails.mail !== "undefined" && graphUserDetails.mail) {

                        const user = await findUserByEmail(graphUserDetails.mail);
                        console.log("DB USER", user, user.id);
                        if(!user) {
                            throw new Error("Cannot find the user in the database")
                        }

                        const tokenDetails = {
                            accessToken: tokenResponse.accessToken,
                            refreshToken: refreshToken(),
                            userId: user.id,
                            expiresAt: tokenResponse.expiresOn,
                            provider: 'microsoft',
                        }

                        // save the access token in the database with the user email
                        let userToken = await findAccessTokenByUserId(user.id);
                        console.log("existing token", userToken);
                        if(userToken) {
                            userToken = await updateAccessToken(tokenDetails);
                        } else {
                            userToken = await saveAccessToken(tokenDetails);
                        }

                        let redirectUrl = `${state.redirectTo}?access_token=${encodeURIComponent(tokenDetails.accessToken)}&expires_at=${encodeURIComponent(tokenDetails.expiresAt)}`;
                        // console.log("Final redirectUrl", redirectUrl);
                        res.redirect(redirectUrl);
                    } else {
                        next(new Error('Unable to verify user details'));
                    }
                } else {
                    next(new Error('Invalid Access Token'));
                }
            } catch (error) {
                next(error);
            }
        } else {
            res.redirect(`/oauth/microsoft/signin?redirect_url=${state.redirectTo}`);
        }
    } else {
        next(new Error('state is missing'));
    }
}

const acquireToken = async (req, res, next) => {

    // create a GUID for csrf
    req.session.csrfToken = cryptoProvider.createNewGuid();

    // encode the state param
    const state = cryptoProvider.base64Encode(
        JSON.stringify({
            csrfToken: req.session.csrfToken,
            redirectTo: '/users/profile'
        })
    );

    const authCodeUrlRequestParams = {
        state: state,
        scopes: ["User.Read"],
    };

    const authCodeRequestParams = {
        scopes: ["User.Read"],
    };

    // trigger the first leg of auth code flow
    return redirectToAuthCodeUrl(req, res, next, authCodeUrlRequestParams, authCodeRequestParams)
}

/**
 * Refresh the access token
 * Uses the access token in the authorization header to match in the DB to validate the user request
 */
const handleRefreshTokenRequest = async (req, res) => {

    try {
        console.log(req.body);

        if(
            !req.headers.authorization ||
            !req.body.auth_provider ||
            !req.body.auth_user
        ) {
            console.log("Credentials missing");
            res.status(401).send("Credentials missing");
            return;
        }

        const authorizationHeader = req.headers.authorization;
        const authProvider = req.body.auth_provider;
        const userEmail = req.body.auth_user;

        if (authorizationHeader) {
            // Extract the token from the authorization header
            const token = authorizationHeader.split(' ')[1];
            // console.log('Auth Token:', token, authProvider);

            const user = await findUserByEmail(userEmail);
            if(!user) {
                console.log(err);
                res.status(403).send("Invalid credentials");
                return;
            }

            // get access token from database
            let accessToken = await findAccessTokenByUserId(user.id);

            if(!accessToken) {
                throw new Error("Access token not found in database");
            }

            console.log("accessToken", accessToken);

            // refresh access token
            const tokenRequest = {
                refreshToken: accessToken.refresh_token,
            };

            const response = await msalInstance.acquireTokenByRefreshToken(tokenRequest);

            const tokenDetails = {
                accessToken: response.accessToken,
                refreshToken: accessToken.refresh_token,
                userId: user.id,
                expiresAt: response.expiresOn,
                provider: 'microsoft',
            }

            // update access token in database
            await updateAccessToken(tokenDetails);

            if(response) {
                res.status(200).send({
                    token: tokenDetails.accessToken,
                    expiresAt: tokenDetails.expiresAt
                });
                return;
            }

            res.status(500).send("Something went wrong");

        }
    } catch(err) {
        console.log(err);
        res.status(500).send("Something went wrong");
    }
}

const handleSignOut = async (req, res) => {
    /**
     * Construct a logout URI and redirect the user to end the
     * session with Azure AD. For more information, visit:
     * https://docs.microsoft.com/azure/active-directory/develop/v2-protocols-oidc#send-a-sign-out-request
     */
    const logoutUri = `${msalConfig.auth.authority}/oauth2/v2.0/logout?post_logout_redirect_uri=${POST_LOGOUT_REDIRECT_URI}`;

    req.session.destroy(() => {
        res.redirect(logoutUri);
    });
}

const refreshToken = () => {
    const tokenCache = msalInstance.getTokenCache().serialize();
    const refreshTokenObject = (JSON.parse(tokenCache)).RefreshToken
    const refreshToken = refreshTokenObject[Object.keys(refreshTokenObject)[0]].secret;
    return refreshToken;
}

module.exports = {
    handleSignIn,
    handleRedirect,
    handleSignOut,
    acquireToken,
    handleRefreshTokenRequest,
};