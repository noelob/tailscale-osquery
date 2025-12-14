package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
	"tailscale.com/client/tailscale/v2"
)

var (
	client = &tailscale.Client{
		Tailnet: os.Getenv("TAILSCALE_TAILNET"),
		APIKey:  os.Getenv("TAILSCALE_API_KEY"),
	}
	socket   = flag.String("socket", "", "Path to osquery socket file")
	timeout  = flag.Int("timeout", 0, "Timeout")
	interval = flag.Int("interval", 0, "Interval")
)

func main() {
	flag.Parse()
	if *socket == "" {
		log.Fatalf(`Usage: %s --socket SOCKET_PATH`, os.Args[0])
	}

	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout),
	)
	serverPingInterval := osquery.ServerPingInterval(
		time.Second * time.Duration(*interval),
	)

	server, err := osquery.NewExtensionManagerServer("tailscale", *socket, serverTimeout, serverPingInterval)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	server.RegisterPlugin(table.NewPlugin("tailscale_devices", DevicesColumns(), DevicesGenerate))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}

// DevicesColumns returns the columns that our table will return.
func DevicesColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("id"),
		table.TextColumn("name"),
		table.TextColumn("authorized"),
		table.TextColumn("user"),
		table.TextColumn("client_version"),
		table.TextColumn("hostname"),
		table.TextColumn("ephemeral"),
		table.TextColumn("external"),
		table.TextColumn("os"),
		table.TextColumn("distro_name"),
		table.TextColumn("distro_version"),
		table.TextColumn("last_seen"),
	}
}

// DevicesGenerate will be called whenever the table is queried. It should return a full table scan.
func DevicesGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	devices, err := client.Devices().ListWithAllFields(ctx)
	if err != nil {
		return nil, err
	}

	var ret []map[string]string

	for _, device := range devices {
		ret = append(ret, map[string]string{
			"id":             device.NodeID,
			"name":           device.Name,
			"authorized":     strconv.FormatBool(device.Authorized),
			"user":           device.User,
			"client_version": device.ClientVersion,
			"hostname":       device.Hostname,
			"ephemeral":      strconv.FormatBool(device.IsEphemeral),
			"external":       strconv.FormatBool(device.IsExternal),
			"os":             device.OS,
			"distro_name":    device.Distro.Name,
			"distro_version": device.Distro.Version,
			"last_seen":      device.LastSeen.Format(time.RFC3339),
		})
	}

	return ret, nil
}
