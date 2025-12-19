.PHONY: build
build:
	go build -o tailscale.ext .
	chmod 555 tailscale.ext