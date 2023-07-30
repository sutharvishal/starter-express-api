const db = require('../config/database');
const {toUTCDate} = require("../helpers/commonHelper");

const findAccessTokenByUserId = async (userId) => {
    const token = await db.query(`SELECT * FROM access_tokens WHERE user_id = '${userId}'`);
    console.log("Find access token", userId, token);
    return token.length > 0 ? token[0] : null;
}

const saveAccessToken = async ({ accessToken, refreshToken, userId, provider, expiresAt  }) => {
    try {
        const formattedExpiryDate = toUTCDate(expiresAt);
        const dateNow = toUTCDate(new Date().toUTCString());
        const result = await db.query(`
          INSERT INTO access_tokens (access_token, refresh_token, user_id, provider, expires_at, created_at, updated_at) 
          VALUES ( '${accessToken}', '${refreshToken}', '${userId}', '${provider}', '${formattedExpiryDate}', '${dateNow}', '${dateNow}' )
        `);

        console.log("savetokenresult", result);

        return result;
    } catch(err) {
        console.log(err);
        return err;
    }
}

const updateAccessToken = async ({ accessToken, refreshToken, userId, provider, expiresAt }) => {
    try{
        const formattedExpiryDate = toUTCDate(expiresAt);
        const dateNow = toUTCDate(new Date().toUTCString());
        const updateResult = await db.query(`
          UPDATE access_tokens
          SET access_token = '${accessToken}', refresh_token = '${refreshToken}', user_id = '${userId}', provider = '${provider}', expires_at = '${formattedExpiryDate}', updated_at = '${dateNow}'
          WHERE user_id = '${userId}';
        `)

        return updateResult;
    } catch(err) {
        return err;
    }
}

module.exports = {
    findAccessTokenByUserId,
    saveAccessToken,
    updateAccessToken
};