# @dougschaefer/shodan

A [swamp](https://github.com/swamp-club/swamp) model for the
[Shodan](https://www.shodan.io) internet-wide scan database. Find and profile
internet-exposed devices — built for auditing the AV/IoT attack surface, but
useful for any exposure reconnaissance.

Every read method is **passive OSINT**: it queries Shodan's existing index and
never connects to, logs into, or exploits a third-party device. The one active
method, `requestScan`, asks Shodan to scan IPs **you own** and spends scan
credits.

## Installation

```bash
swamp extension pull @dougschaefer/shodan
```

## Authentication

One Shodan API key, resolved from vault and passed as a global argument. Store
it first (piped from stdin so it never lands in shell history):

```bash
pbpaste | swamp vault put asei shodan-api-key      # macOS
# or:  printf %s "$KEY" | swamp vault put asei shodan-api-key
```

Then create an instance whose global args reference the vault:

```bash
swamp model create @dougschaefer/shodan shodan \
  --global-arg 'apiKey=${{ vault.get(asei, shodan-api-key) }}'
```

## Methods

| Method        | Cost            | Purpose                                                         |
| ------------- | --------------- | -------------------------------------------------------------- |
| `accountInfo` | free            | Plan and remaining query/scan credits. Validates the key.      |
| `search`      | 1 query credit / 100 results | Search and return trimmed device records + facets. |
| `count`       | **free**        | Total results + facets without spending query credits.         |
| `host`        | free*           | Full banner history, open ports, and CVEs for one IP.          |
| `internetdb`  | **free, keyless** | Open ports, CPEs, tags, and CVEs for one IP (no API key).    |
| `requestScan` | scan credits    | **Active.** Request an on-demand scan of IPs you own.          |

\* `host` lookups draw on your monthly allowance per Shodan's terms.

## Examples

```bash
# Confirm the key works and see your credits
swamp model method run shodan accountInfo

# How many of a device type are exposed, scoped to a city — costs nothing
swamp model method run shodan count \
  --input 'query=product:"Crestron"' --input 'city=Fort Wayne' \
  --input 'facets=org,country,port'

# The wall of shame: real exposed devices
swamp model method run shodan search \
  --input 'query=product:"Crestron"' --input 'country=US' --input 'limit=25'

# Drill into one address (CVEs included)
swamp model method run shodan host --input 'ip=192.0.2.4'

# Keyless, zero-credit lookup
swamp model method run shodan internetdb --input 'ip=192.0.2.4'
```

## Workflow

`shodan-av-recon` chains `accountInfo` → `count` → `search` for a one-command
recon run, scoped by an optional city/country. See
[shodan-av-recon.yaml](../../workflows/shodan-av-recon.yaml).

```bash
swamp workflow run @dougschaefer/shodan-av-recon \
  --input '{"query":"product:\"Crestron\"","city":"Fort Wayne","limit":25}'
```

## Responsible use

Querying Shodan is legal passive reconnaissance. Displaying results is fine —
it is public data. Do **not** use the results to connect to or test devices you
do not own or have written authorization to assess. Use `requestScan` only
against your own address space.

## License

MIT — see [LICENSE.txt](./LICENSE.txt).
