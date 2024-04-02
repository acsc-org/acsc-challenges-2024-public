FROM ubuntu:22.04

ENV user runner

RUN apt-get update
RUN apt-get -y install socat

RUN adduser $user

ADD ./challenge/flag /home/$user/flag
ADD ./challenge/flag_ba435220d789b8cb.txt /home/$user/flag_ba435220d789b8cb.txt
ADD ./challenge/main /home/$user/main

RUN chown root:$user /home/$user/
RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/flag_ba435220d789b8cb.txt
RUN chown root:$user /home/$user/main

RUN chmod 755 /home/$user/main
RUN chmod 440 /home/$user/flag
RUN chmod 440 /home/$user/flag_ba435220d789b8cb.txt

WORKDIR /home/$user
USER runner
CMD socat -T 90 TCP-LISTEN:10801,reuseaddr,fork EXEC:/home/$user/main
