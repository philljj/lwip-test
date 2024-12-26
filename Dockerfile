FROM debian:10 AS builder

RUN apt-get update && \
    apt-get install -y unzip libpcap-dev build-essential git cmake && \
    apt-get install -y autoconf libtool && \
    rm -rf /var/lib/dpkg/lists/*

WORKDIR /src

COPY . lwip-echo

RUN cd /src/lwip-echo/wolfssl && ./autogen.sh && \
  ./configure --disable-shared --enable-static --enable-cryptonly \
  --enable-des3 --enable-aesgcm-stream --disable-examples && \
  make && make install

WORKDIR /build

RUN cmake /src/lwip-echo/ && make -j

FROM debian:10 AS runner

# Add this to RUN command for debugging.
#    apt-get install -y valgrind && \
RUN apt-get update && \
    apt-get install -y libpcap0.8 && \
    apt-get install -y ncat && \
    rm -rf /var/lib/dpkg/lists/*

WORKDIR /app

COPY --from=builder /build/lwip-runner .

CMD /app/lwip-runner
#CMD valgrind --tool=memcheck --track-origins=yes --leak-check=full \
# --show-leak-kinds=all /app/lwip-runner
