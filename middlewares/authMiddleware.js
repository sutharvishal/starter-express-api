var { getUserProfileDetails } = require('../helpers/OAuthProxyHelper');

const isAuthenticated = async (req, res, next) => {
    console.log("req.params", req.params);

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

        let user = null;

        if(authProvider == "microsoft") {
            try {
                const userGraphDetails = await getUserProfileDetails(token, authProvider);
                console.log("graphUserDetails", userGraphDetails);
                console.log(userGraphDetails.mail, userEmail);
                if(userGraphDetails.mail && userGraphDetails.mail == userEmail) {
                    // need to fetch the actual user from the database
                    // currently we don't have users table so we are using the response received from MS Graph API
                    user = userGraphDetails;
                }
            } catch (err) {
                console.log(err);
                res.status(403).send("Invalid credentials");
                return;
            }
        }

        if(user) {
            console.log("Authenticated");
            next();
        }
    }
}

module.exports = {
    isAuthenticated
}