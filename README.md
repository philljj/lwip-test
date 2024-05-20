# LWIP Echo Test

This is an extremely basic demo application that uses the LWIP stack via PCAP to echo anything sent to it.

## Prerequisites

Install `docker` and `docker-compose`:

```sh
sudo dnf install docker
```

```sh
sudo dnf install docker-compose
```

Docker daemon is running:

```sh
sudo dockerd
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

This will stay running until cancelled with Ctrl-C. In a new terminal, connect to the test service. The IP is hard coded to `172.17.0.5` and the port to `11111`:

```sh
nc 172.17.0.5 11111
```

Anything you type into this console will echo on the other one. For example, if you type "hello world" you will see:

```
echo_init: pcb: e42f6d80
echo_init: tcp_bind: 0
echo_init: listen-pcb: e42f6e60
echo_msgaccept called
Got: hello world
```

You can exit the app and nc with Ctrl-C.

Also, this example should appear as a new docker network:

```sh
docker network ls
NETWORK ID     NAME              DRIVER    SCOPE
646a1de4ebf4   bridge            bridge    local
9da295e5a554   host              host      local
5814aa6cd305   linux-lwip_echo   bridge    local
e3fd77c750de   none              null      local
```

You can get detailed info with `docker network inspect linux-lwip_echo`.

## Notes

The `lwip-include/arch` directory is a copy of the lwIP directory from `contrib/ports/unix/port/include/arch`.
