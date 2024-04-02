FROM sagemath/sagemath:latest

USER root
RUN apt-get update && apt-get install socat -y
USER sage

WORKDIR /app
COPY ./challenge/task.sage /app
COPY ./challenge/flag.txt /app
EXPOSE 17777

CMD "socat \"TCP-LISTEN:17777,reuseaddr,fork\" \"EXEC:sage task.sage,nofork,stderr\""