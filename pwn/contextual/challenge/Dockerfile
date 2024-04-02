FROM ubuntu:22.04@sha256:2b7412e6465c3c7fc5bb21d3e6f1917c167358449fecac8176c6e496e5c1f05f
MAINTAINER James

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install xinetd -qy
RUN useradd -m Contextual

COPY ./share /home/Contextual
COPY ./xinetd /etc/xinetd.d/contextual

RUN chown -R root:root /home/Contextual
RUN chmod -R 755 /home/Contextual

CMD ["/usr/sbin/xinetd","-dontfork"]
