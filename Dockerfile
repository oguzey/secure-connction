FROM ubuntu
RUN apt-get update
RUN apt-get install -y gcc make cmake wget unzip perl perl-base vim gdb

RUN wget https://github.com/openssl/openssl/archive/master.zip
RUN unzip master.zip
RUN cd openssl-master && ./config && make
RUN cd openssl-master && make test || echo "Tests fails"
RUN cd openssl-master && make install
RUN ldconfig

RUN mkdir /src /ssl-certificates
COPY ./src/ /src/
COPY ./build.sh /build.sh
COPY ./ssl-certificates /ssl-certificates

RUN /build.sh
ENV PATH "/src/build:$PATH"

CMD ["secure-server"]

