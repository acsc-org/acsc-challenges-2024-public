const mysql = require("mysql2/promise");
require("dotenv").config();

class DataBaseHandler {
  constructor() {
    this.connection = mysql.createPool({
      host: process.env.MYSQL_HOST,
      user: process.env.MYSQL_USER,
      database: process.env.MYSQL_DATABASE,
      password: process.env.MYSQL_PASSWORD,
      port: process.env.MYSQL_PORT,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });
  }

  async queryAsync(query, params) {
    return await this.connection.query(query, params);
  }
}

module.exports = new DataBaseHandler();
