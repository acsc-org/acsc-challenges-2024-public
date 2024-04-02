FROM ubuntu:22.04@sha256:77906da86b60585ce12215807090eb327e7386c8fafb5402369e421f44eff17e as chroot

WORKDIR /
RUN apt-get update && apt-get -y dist-upgrade && apt-get -y upgrade && apt-get -yq --no-install-recommends install wget python3
RUN /usr/sbin/useradd --no-create-home -u 1000 user

COPY chall /home/user/
RUN chmod 111 /home/user/chall

FROM gcr.io/kctf-docker/challenge@sha256:501458c0426acc3b5a74a661791271faf0dca6555b46bfb76f944d2558bd08d5

COPY --from=chroot / /chroot

COPY nsjail.cfg /home/user/
RUN chmod 644 /home/user/nsjail.cfg

#COPY pow.conf /kctf/pow/

CMD kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:9999,reuseaddr,fork \
      EXEC:"kctf_pow nsjail --config /home/user/nsjail.cfg -- /bin/bash",pty,ctty,stderr,raw,echo=0
