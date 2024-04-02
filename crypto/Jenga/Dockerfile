FROM python:3.12-alpine

ENV USER chall

USER root
RUN apk add socat
RUN adduser -D -g "" $USER

USER $USER
WORKDIR /app
COPY ./challenge/Jenga.py /app
COPY ./challenge/task.py /app
COPY ./challenge/flag /app

CMD ["socat", "TCP-LISTEN:39425,reuseaddr,fork", "EXEC:python3 task.py,nofork,stderr"]