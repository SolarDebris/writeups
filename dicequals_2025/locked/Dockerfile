FROM ubuntu:22.04 AS base

#FROM pwn.red/jail


RUN apt-get update && \ 
    apt-get install -y gdb gdbserver

#COPY --from=base / /srv
COPY run.sh /app/run
COPY locked_room libc.so flag.txt /app/
