CREATE database admin_debug;
use mysql;
CREATE user 'demo'@'%' identified by 'demo';
GRANT SELECT, CREATE TEMPORARY TABLES on admin_debug.* to 'demo'@'%';
FLUSH PRIVILEGES;