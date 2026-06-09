# Vultrunbound
DNS Helper For Vultr

## Overview

Vultr provides an api interface to gather data, using the api we pull data from vultr and then writeout dns settings for virtual machines for either a local hosts file or for unbound dns using the unbound-control feature

## Configuration

A config file name config.json must be placed in any of current dir, root/.vultrunbound or /etc/vultrunbound/ At minimum the file should have the vultr_key, other settings may be set from cmd arguments or put in the configuration, see the config.json.example

## Usage

### Hosts File

```
vultrunbound --output=hosts --target=/etc/hosts
```

### Unbound

```
vultrunbound --output=unbound-control
```

### Server

Server mode keeps running, syncs entries from Vultr every five minutes by default,
and caches the latest entries to `.vultrdns`.

```
vultrunbound --server --listen=:8080 --vultrdns=./.vultrdns
```

Endpoints:

```
GET /entries
GET /hosts
```

`/entries` returns the JSON DNS entries. `/hosts` returns hosts-file text.
Both responses include `X-ModifiedAt` with the `.vultrdns` cache file mtime.

### Client

Client mode pulls DNS data from a server and writes it locally using the selected
output mode.

```
vultrunbound --client=192.168.4.1 --output=hosts --target=/etc/hosts
vultrunbound --client=192.168.4.1 --output=unbound-control
```

* Note arguments are optional and may be placed in the configuration file alternatively
