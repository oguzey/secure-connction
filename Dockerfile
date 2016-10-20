FROM ubuntu
RUN apt-get update
RUN apt-get install -y gcc make cmake wget unzip perl perl-base vim gdb

RUN wget https://github.com/openssl/openssl/archive/master.zip
RUN unzip master.zip
RUN cd openssl-master && ./config && make
RUN cd openssl-master && make test || echo "Tests fails"
RUN cd openssl-master && make install
RUN ldconfig

RUN mkdir /src /src/build /ssl-certificates
COPY ./server.c ./client.c ./common.h ./CMakeLists.txt /src/
COPY ./ssl-certificates /ssl-certificates

RUN cd /src/build && cmake .. && make
ENV PATH "/src/build:$PATH"

CMD ["secure-server"]

