.PHONY: build test release install

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o goserverpanel ./cmd/panel

test:
	go vet ./... && go test ./...

release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/goserverpanel-linux-amd64 ./cmd/panel
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o dist/goserverpanel-linux-arm64 ./cmd/panel

install: build
	install -m 0755 goserverpanel /usr/local/bin/goserverpanel
	install -d -m 0700 /etc/goserverpanel /var/lib/goserverpanel
	test -f /etc/goserverpanel/config.yaml || install -m 0600 config.yaml /etc/goserverpanel/config.yaml
	install -m 0644 deploy/goserverpanel.service /etc/systemd/system/goserverpanel.service
	systemctl daemon-reload && systemctl enable --now goserverpanel
