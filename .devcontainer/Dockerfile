FROM golang:1

# Configure apt
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get -y install --no-install-recommends apt-utils dialog less vim 2>&1

## YOUR DOCKERFILE CONTENT GOES HERE
ENV DEBIAN_FRONTEND=dialog

RUN go get -u \
    github.com/uudashr/gopkgs/v2/cmd/gopkgs \
    github.com/ramya-rao-a/go-outline \
    github.com/cweill/gotests \
    github.com/fatih/gomodifytags \ 
    github.com/josharian/impl \ 
    github.com/haya14busa/goplay/cmd/goplay \
    github.com/go-delve/delve/cmd/dlv \
    golang.org/x/lint/golint \
    golang.org/x/tools/gopls  2>&1
