const mysql = require('mysql');

// Create a connection
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'redoxygen',
  timezone: 'utc',
});

// Define your database configurations
// const database = new Sequelize({
//   dialect: 'mysql',
//   host: 'localhost',
//   port: 3306,
//   username: 'root',
//   password: '',
//   database: 'redoxygen',
// });



// Query function to execute SQL queries
function query(sql, values) {
  return new Promise((resolve, reject) => {
    pool.getConnection((error, connection) => {
      if (error) {
        reject(error);
        return;
      }

      connection.query(sql, values, (error, results) => {
        connection.release();

        if (error) {
          reject(error);
          return;
        }

        resolve(results || null);
      });
    });
  });
}

module.exports = {
  query,
};