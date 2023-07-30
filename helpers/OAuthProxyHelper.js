var MicrosoftGraphHelper = require('./MicrosoftGraphHelper');

const getUserProfileDetails = async (token, provider) => {
    try{
        if(typeof token && provider) {
            let profileDetails = null;
            switch(provider) {
                case "microsoft":
                    profileDetails = MicrosoftGraphHelper.getUserProfileDetails(token);
                    break;
            }

            if(!profileDetails) {
                throw new Error("Unable to get profile details, make sure the provider and the access token is valid");        
            }

            return profileDetails;
        } else {
            throw new Error("Unable to get profile details, invalid parameters were given");    
        }
    } catch(err) {
        throw new Error(err.message);
    }
}

module.exports = {
    getUserProfileDetails
}