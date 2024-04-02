FROM ubuntu:20.04
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Seoul

RUN apt update
RUN apt install mysql-server -y
RUN apt install nginx php7.4-fpm -y
RUN apt install gcc -y

COPY ./entrypoint.sh /entrypoint.sh
COPY ./web /var/www/html
COPY ./configs/default.conf /etc/nginx/sites-available/default
COPY ./configs/php.ini /etc/php/7.4/fpm/php.ini
COPY ./configs/my.cnf /etc/mysql/my.cnf
COPY ./configs/init.sql /tmp/init.sql
COPY ./flag.c /tmp/flag.c

RUN rm /var/www/html/index.nginx-debian.html
RUN gcc /tmp/flag.c -o /flag && rm /tmp/flag.c
RUN chown -R www-data /var/lib/mysql && chown -R www-data /var/run/mysqld
RUN chmod 755 /etc/mysql/my.cnf
RUN chmod 711 /flag
RUN chmod 755 /entrypoint.sh

EXPOSE 3306
ENTRYPOINT /entrypoint.sh
