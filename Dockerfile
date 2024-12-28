FROM debian:latest

RUN apt-get update
RUN apt-get install apt-utils -y;
RUN apt-get install clang -y ;
RUN apt-get install make -y;
RUN apt-get install binutils -y
RUN apt-get install git -y
RUN apt-get install -y gcc make

RUN apt-get install inetutils-traceroute -y
RUN apt-get install vim -y
RUN apt-get install tcpdump -y
RUN apt-get install nmap -y;
RUN apt-get install libpcap-dev -y;
RUN apt install net-tools -y
RUN apt install valgrind -y
WORKDIR /app
# COPY . .

CMD ["/bin/bash"]