# LWIP Echo Test

This is a basic demo application that uses the LWIP stack via PCAP to echo back
anything sent to it.

It supports UDP, TCP, IPv4, and IPv6, on client and server side.

## Prerequisites

Install `docker`:

```sh
sudo dnf install docker
```

Docker daemon is running. If testing IPv4, run like this:

```sh
sudo dockerd
```

If testing IPv6, run dockerd like this:

```sh
  # ip6tables rules are only available if experimental features are enabled.
  # From this:
  #   https://docs.docker.com/config/daemon/ipv6/
  sudo dockerd --experimental --ip6tables --ipv6 \
    --fixed-cidr-v6 2001:db8::/104 \
    --default-gateway-v6 2001:db8::2
```

Clone or copy lwip src dir tree to this directory:

```sh
ls
CMakeLists.txt  Dockerfile  echo.c  echo.h  LICENSE  lwip  lwip-include  lwip.patch  main.c  README.md
```

## Usage

Build the docker image:

```sh
sudo docker build -t lwip-test .
```

Run the newly created docker image:

```sh
docker run -it lwip-test
```

This will stay running until cancelled with Ctrl-C. In a new terminal, connect
to the test service. The IP is hard coded to `2001:db8::1` when using IPv6, and
`172.17.0.5` for IPv4, and the port to `11111`:

```sh
nc -u6 2001:db8::5 11111
```

or

```sh
nc 172.17.0.5 11111
```

Anything you type into this console will echo on the other one.
You can exit the app and nc with Ctrl-C.

Also, this example should appear as a new docker container and
network:

```sh
$sudo docker container ls
CONTAINER ID   IMAGE       COMMAND                  CREATED              STATUS              PORTS     NAMES
7dc737cb4030   lwip-test   "/bin/sh -c /app/lwi…"   About a minute ago   Up About a minute             pedantic_morse

$sudo docker network ls
NETWORK ID     NAME      DRIVER    SCOPE
be4913c77e56   bridge    bridge    local
1b26983fe372   host      host      local
c4998617444d   none      null      local
```

You can get detailed info with `docker network inspect bridge` and
 `docker container inspect <container id>`.

## Configuring UDP, TCP, IPv4, IPv6, client and server

The choice of UDP/TCP and client/server is hard-coded in `echo.c` here:

```
/* globals */
/* Toggle tcp/udp at build time. */
static int use_tcp = 0;
/* Toggle server/client mode. */
static int am_server = 0;
```

The choice of IPv4 vs IPv6 is set in `lwip-include/lwipopts.h` here

```
// Enable LWIP_IPV4 or LWIP_IPV6, but
// not both.
#define LWIP_IPV4                       0
#define LWIP_IPV6                       1
```

## Notes

The `lwip-include/arch` directory is a copy of the lwIP directory from
`contrib/ports/unix/port/include/arch`.
