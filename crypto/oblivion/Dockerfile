FROM sagemath/sagemath:latest

USER root
RUN apt-get update && apt-get install socat -y
USER sage

WORKDIR /app
COPY ./chal/chall.sage /app
COPY ./chal/flag.txt /app
EXPOSE 1234

CMD "socat \"TCP-LISTEN:1234,reuseaddr,fork\" \"EXEC:sage chall.sage,nofork,stderr\""