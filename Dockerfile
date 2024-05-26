FROM debian:10 AS builder

RUN apt-get update && \
    apt-get install -y unzip libpcap-dev build-essential git cmake && \
    apt-get install -y autoconf libtool && \
    rm -rf /var/lib/dpkg/lists/*

WORKDIR /src

COPY . lwip-echo

RUN cd /src/lwip-echo/wolfssl && ./autogen.sh && \
  ./configure --disable-shared --enable-static --enable-cryptonly --disable-examples && \
  make

WORKDIR /build

RUN cmake /src/lwip-echo/ && make -j

FROM debian:10 AS runner

RUN apt-get update && apt-get install -y libpcap0.8 && \
    apt-get install -y ncat && \
    rm -rf /var/lib/dpkg/lists/*

WORKDIR /app

COPY --from=builder /build/lwip-runner .

CMD /app/lwip-runner
#ENTRYPOINT ["/bin/bash", "-c", "/app/lwip-runner"]
