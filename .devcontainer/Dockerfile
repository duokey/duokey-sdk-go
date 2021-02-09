FROM golang:1

# Configure apt
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get -y install --no-install-recommends apt-utils dialog less vim 2>&1

## YOUR DOCKERFILE CONTENT GOES HERE
ENV DEBIAN_FRONTEND=dialog
