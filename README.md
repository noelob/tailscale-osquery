# A Tailscale Extension for [osquery](https://osquery.io/)
 
```bash
osquery> select os, count(1) as count from tailscale_devices group by os;
+---------+-------+
| os      | count |
+---------+-------+
| android | 36    |
| freebsd | 1     |
| iOS     | 100   |
| linux   | 505   |
| macOS   | 300   |
| plan9   | 2     |
| windows | 33    |
+---------+-------+

```

# Setup

```bash
# Build the extension
make build

# Visit https://login.tailscale.com/admin/settings/general for tailnet id
# Visit https://login.tailscale.com/admin/settings/keys for api access token
export TAILSCALE_TAILNET='<your-tailnet-id>' 
export TAILSCALE_API_KEY='<your-tailscale-api-access-token>'

osqueryi --extension ./tailscale.ext 
```