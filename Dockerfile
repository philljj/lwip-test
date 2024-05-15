FROM debian:10 AS builder

RUN apt update && apt install -y unzip libpcap-dev build-essential git cmake && rm -rf /var/lib/dpkg/lists/*

WORKDIR /src

#RUN git clone https://github.com/lwip-tcpip/lwip

# Use master.
#RUN git clone https://github.com/philljj/lwip.git

# Use old 2_0_3
RUN git clone https://github.com/philljj/lwip.git && cd lwip && git checkout stable-2_0_3_patched && cd ../

COPY . lwip-echo

WORKDIR /build

RUN cmake /src/lwip-echo/ && make -j

FROM debian:10 AS runner

RUN apt update && apt install -y libpcap0.8 && rm -rf /var/lib/dpkg/lists/*

WORKDIR /app

COPY --from=builder /build/lwip-runner .

CMD /app/lwip-runner
#ENTRYPOINT ["/bin/bash", "-c", "/app/lwip-runner"]
