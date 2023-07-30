const db = require('../config/database');

const findUserByEmail = async (userEmail) => {
    const user = await db.query(`SELECT * FROM users WHERE email = '${userEmail}'`);
    console.log("Find user", userEmail, user);
    return user.length > 0 ? user[0] : null;
}


module.exports = {
    findUserByEmail
};