package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/kofalt/go-memoize"
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

	cache = memoize.NewMemoizer(90*time.Second, 10*time.Minute)
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
	server.RegisterPlugin(table.NewPlugin("tailscale_users", UsersColumns(), UsersGenerate))
	server.RegisterPlugin(table.NewPlugin("tailscale_tags", TagsColumns(), TagsGenerate))
	server.RegisterPlugin(table.NewPlugin("tailscale_device_tags", DeviceTagsColumns(), DeviceTagsGenerate))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}

// DevicesColumns returns the columns for the tailscale_devices table.
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
	devices, err, _ := memoize.Call(cache, "devices", func() ([]tailscale.Device, error) {
		return client.Devices().ListWithAllFields(ctx)
	})

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

// UsersColumns returns the columns for the tailscale_users table.
func UsersColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("id"),
		table.TextColumn("display_name"),
		table.TextColumn("login_name"),
		table.TextColumn("tailnet_id"),
		table.TextColumn("type"),
		table.TextColumn("role"),
		table.TextColumn("status"),
		table.IntegerColumn("device_count"),
		table.TextColumn("connected"),
		table.TextColumn("created"),
		table.TextColumn("last_seen"),
	}
}

// UsersGenerate will be called whenever the table is queried. It should return a full table scan.
func UsersGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	users, err, _ := memoize.Call(cache, "users", func() ([]tailscale.User, error) {
		return client.Users().List(ctx, nil, nil)
	})

	if err != nil {
		return nil, err
	}

	var ret []map[string]string

	for _, user := range users {
		ret = append(ret, map[string]string{
			"id":           user.ID,
			"display_name": user.DisplayName,
			"login_name":   user.LoginName,
			"tailnet_id":   user.TailnetID,
			"type":         string(user.Type),
			"role":         string(user.Role),
			"status":       string(user.Status),
			"device_count": strconv.Itoa(user.DeviceCount),
			"connected":    strconv.FormatBool(user.CurrentlyConnected),
			"created":      user.Created.Format(time.RFC3339),
			"last_seen":    user.LastSeen.Format(time.RFC3339),
		})
	}

	return ret, nil
}

// TagsColumns returns the columns for the tailscale_tags table.
func TagsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("tag"),
	}
}

// TagsGenerate will be called whenever the table is queried. It should return a full table scan.
func TagsGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	devices, err, _ := memoize.Call(cache, "devices", func() ([]tailscale.Device, error) {
		return client.Devices().ListWithAllFields(ctx)
	})

	if err != nil {
		return nil, err
	}

	tags := stringSet{}
	for _, device := range devices {
		for _, tag := range device.Tags {
			tags.Add(tag)
		}
	}

	var ret []map[string]string
	for t := range tags {
		ret = append(ret, map[string]string{
			"tag": t,
		})
	}
	return ret, nil
}

// DeviceTagsColumns returns the columns for the tailscale_device_tags table.
func DeviceTagsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("id"),
		table.TextColumn("tag"),
	}
}

// DeviceTagsGenerate will be called whenever the table is queried. It should return a full table scan.
func DeviceTagsGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	devices, err, _ := memoize.Call(cache, "devices", func() ([]tailscale.Device, error) {
		return client.Devices().ListWithAllFields(ctx)
	})

	if err != nil {
		return nil, err
	}

	var ret []map[string]string

	for _, device := range devices {
		for _, tag := range device.Tags {
			ret = append(ret, map[string]string{
				"id":  device.NodeID,
				"tag": tag,
			})
		}
	}

	return ret, nil
}
