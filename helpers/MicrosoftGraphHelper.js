var fetch = require('./authenticatedFetch');

var { GRAPH_ME_ENDPOINT } = require('../config/microsoftAuthConfig');

const GraphAPIError = (err) => {
    throw new Error('Error occured while calling graph API: ' + err.message);
};

const MicrosoftGraphHelper = {
    getUserProfileDetails: async (accessToken) => {
        try {
            const graphResponse = await fetch(GRAPH_ME_ENDPOINT, accessToken);
            return graphResponse;
        } catch (err) {
            GraphAPIError(err);
        }
    }
}

module.exports = MicrosoftGraphHelper;