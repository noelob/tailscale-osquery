.PHONY: build
build:
	go build -o tailscale.ext tailscale.go
	chmod 555 tailscale.ext