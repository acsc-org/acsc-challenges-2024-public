/***CREATING ALL TABLES*/
CREATE TABLE users (
  user_id INT PRIMARY KEY AUTO_INCREMENT NOT NULL,
  username VARCHAR(100) NULL,
  password VARCHAR(100) NULL,
  two_factor TINYINT(1) NULL,  
  secret VARCHAR(100) NULL,
  trusted_device VARCHAR(100) NULL
);


/* INSERT DATA */
INSERT INTO users (username,password,two_factor,secret,trusted_device)
VALUES ('admin','admin', 1, 'HFCWEZKEOFAFOILCFJYVQ5SRHZZWWY3M', '2ddab7dd181163babbbae9626c05d05c3c1d0b26');

