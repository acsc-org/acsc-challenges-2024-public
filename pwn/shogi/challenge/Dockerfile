FROM ubuntu:22.04@sha256:2b7412e6465c3c7fc5bb21d3e6f1917c167358449fecac8176c6e496e5c1f05f
MAINTAINER James

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install xinetd -qy
RUN useradd -m Shogi

COPY ./share /home/Shogi
COPY ./xinetd /etc/xinetd.d/shogi

RUN chown -R root:root /home/Shogi
RUN chmod -R 755 /home/Shogi

CMD ["/usr/sbin/xinetd","-dontfork"]
