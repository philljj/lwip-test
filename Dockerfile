FROM debian:10 AS builder

RUN apt update && apt install -y unzip libpcap-dev build-essential git cmake \
  && rm -rf /var/lib/dpkg/lists/*

WORKDIR /src

COPY . lwip-echo

WORKDIR /build

RUN cmake /src/lwip-echo/ && make -j

FROM debian:10 AS runner

RUN apt update && apt install -y libpcap0.8 && rm -rf /var/lib/dpkg/lists/*

WORKDIR /app

COPY --from=builder /build/lwip-runner .

CMD /app/lwip-runner
#ENTRYPOINT ["/bin/bash", "-c", "/app/lwip-runner"]
