FROM ubuntu:latest

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates \
    apt-transport-https

RUN gpg --keyserver pgp.mit.edu --recv EC992669 && \
    gpg --export --armor EC992669 | apt-key add - && \
    echo 'deb https://archives.gitwarden.com/deb squeeze main' | tee /etc/apt/sources.list.d/gitwarden.list && \
    apt-get update && \
    apt-get install gitwarden-agent

CMD [ "gitwarden-agent", "run" ]
