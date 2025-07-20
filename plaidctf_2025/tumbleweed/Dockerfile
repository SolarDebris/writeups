# docker build -t tumble .
# docker run --rm -p 1337:1337 tumble
FROM ubuntu:22.04@sha256:ed1544e454989078f5dec1bfdabd8c5cc9c48e0705d07b678ab6ae3fb61952d2

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y socat

RUN mkdir /home/tumble
COPY ./tumbleweed /home/tumble/
RUN chmod +x /home/tumble/tumbleweed

COPY ./flag /flag
RUN chmod 444 /flag

RUN useradd -m tumble
USER tumble

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/home/tumble/tumbleweed"]
EXPOSE 1337
