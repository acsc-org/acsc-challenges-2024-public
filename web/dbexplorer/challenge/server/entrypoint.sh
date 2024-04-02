#!/bin/bash

service php7.4-fpm start
service nginx start
mysqld &

echo "Waiting 5 sec for mysql booting..."
sleep 5s

dbinit=`mysql -e "select 1 from mysql.user where user='demo'"`
if [[ $dbinit != *"1"* ]]; then
    echo "DB initlizing..."
    mysql < /tmp/init.sql
fi

echo "Done."

while true
do
    echo "Restarting mysql..."
    service mysql stop && mysqld &
    sleep 30
done
