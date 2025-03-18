# ssh-teepee

Vibe-coded ssh tarpit through the power of grok3.

Traps ssh clients in an endless banner exchange.

## Features

- [X] Looks up and stores GeoIP data (country, lat, lon) from maxmind database
- [X] Looks up and stores asn, prefix, net from IPDB database
- [X] Keeps track of
  - IP address (ipv6 + ivp4 mapped to ipv6)
  - Currently active connections from same IP
  - Max concurrency per IP
  - Total connections from an IP
  - Total time wasted per IP
  - First, last seen datetime
  - SSH version string(s) used by an IP
- [X] Updater to ban tarpit clients from other services (like ingress-nginx)

## TODO

- [ ] Make policy-updater ban larger prefix or net based on configurable thresholds (connections, total time, max concurrent)
- [ ] Automated abuse reports to known cloud provider ASNs
- [ ] Update GeoLite2-City and ipnetdb


## Usage

1. Plop in TARPIT_DATABASE_PASSWORD in an .env file to set the database password
1. Build local container using `docker compose build`
1. Start in background using `docker compose up -d`
1. Check logs `docker compose logs -f`

### Inspect database

1. Check connected client list with `docker compose exec db psql -h localhost -U postgres -c "select * from ssh_connections;"


## Grafana

Import `grafana/dashboard.json` into Grafana 10 or newer, make sure to set up a data source that can read the database and configure that in the dashboard.
