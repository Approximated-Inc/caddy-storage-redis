# Redis Storage module for Caddy / Certmagic

This is comprehensive rewrite of the [gamalan/caddy-tlsredis](https://github.com/gamalan/caddy-tlsredis) Redis storage plugin for Caddy.  Some highlights of this new version:

* Fixes some logic issues with configuration parsing
* Introduces a new storage compression option
* Features a Sorted Set indexing algorithm for more efficient directory traversal
* Implements support for Redis Cluster and Sentinel / Failover servers

The plugin uses the latest version of the [go-redis/redis](https://github.com/go-redis/redis) client and [redislock](https://github.com/bsm/redislock) for the locking mechanism. See [distlock](https://redis.io/topics/distlock) for more information on the lock algorithm.

## Build Instructions

To build this module with Caddy Server v2.10.2 and older you must use the v1.5.x release:

```
xcaddy build v2.10.2 --with github.com/pberkel/caddy-storage-redis@v1.5.0
```

Caddy Server v2.11.1 and newer can be built with the latest version of this module:

```
xcaddy build --with github.com/pberkel/caddy-storage-redis
```

## Upgrading

Previous configuration options from [gamalan/caddy-tlsredis](https://github.com/gamalan/caddy-tlsredis) are generally compatible except the following:
- `CADDY_CLUSTERING_REDIS_*` environment variables have been removed. See the  below configuration example to configure this module using environment variables.
- When using the JSON config format directly, be aware of these differences between the old plugin and this plugin:
  - The `address`, `host`, and `port` config fields are now arrays of strings to allow for clustering. The old format was only a string.
  - The old plugin had a config field for `value_prefix`, which has been deprecated and is not included in this plugin.
  - The config field `aes_key` is now named `encryption_key`.
  - The `timeout` config field used to accept only an integer however now accepts only a string.

Upgrading to this module from [gamalan/caddy-tlsredis](https://github.com/gamalan/caddy-tlsredis) will require an [export storage](https://caddyserver.com/docs/command-line#caddy-storage) from the previous installation then [import storage](https://caddyserver.com/docs/command-line#caddy-storage) into a new Caddy server instance running this module.  The default `key_prefix` has been changed from `caddytls` to `caddy` to provide a simpler migration path so keys stored by the [gamalan/caddy-tlsredis](https://github.com/gamalan/caddy-tlsredis) plugin and this module can co-exist in the same Redis database.

## Configuration

### Simple mode (Standalone)

Enable Redis storage for Caddy by specifying the module configuration in the Caddyfile:
```
{
    // All values are optional, below are the defaults
    storage redis {
        host           127.0.0.1
        port           6379
        address        127.0.0.1:6379 // derived from host and port values if not explicitly set
        username       ""
        password       ""
        db             0
        timeout        5
        key_prefix     "caddy" // should not contain any leading or trailing '/' characters nor '.' or '..' path segments
        encryption_key ""      // default no encryption; enable by specifying a secret key containing 32 characters (longer keys will be truncated)
        client_name    ""      // optional: connection name shown in CLIENT LIST
        compression    false   // compression algorithm: 'flate' (raw DEFLATE), 'zlib', or 'false' (no compression, the default). Legacy boolean 'true' maps to 'flate'
        tls_enabled    false
        tls_insecure   false
    }
}

:443 {

}
```
Note that `host` and `port` values can be configured (or accept the defaults) OR an `address` value can be specified, which will override the `host` and `port` values.

Here's the same config as above, but in JSON format (which Caddy parses all configs into under the hood):
```json
{
    "storage": {
        "address": [
            "127.0.0.1:6379"
        ],
        "client_type": "simple",
        "compression": false,
        "db": 0,
        "encryption_key": "",
        "host": [
            "127.0.0.1"
        ],
        "key_prefix": "caddy",
        "master_name": "",
        "module": "redis",
        "password": "",
        "port": [
            "6379"
        ],
        "route_by_latency": false,
        "route_randomly": false,
        "timeout": "5",
        "tls_enabled": false,
        "tls_insecure": false,
        "tls_server_certs_path": "",
        "tls_server_certs_pem": "",
        "username": ""
    },
    "apps": {
        "http": {
            "servers": {
                "srv0": {
                    "listen": [
                        ":443"
                    ]
                }
            }
        }
    }
}
```

The module supports [environment variable substitution](https://caddyserver.com/docs/caddyfile/concepts#environment-variables) within Caddyfile parameters:
```
{
    storage redis {
        username       "{$REDIS_USERNAME}"
        password       "{$REDIS_PASSWORD}"
        db             "{$REDIS_DB}"
        encryption_key "{$REDIS_ENCRYPTION_KEY}"
        compression    "{$REDIS_COMPRESSION}"
    }
}
```

NOTE however the following configuration options do not (yet) support runtime substitution:

- tls_enabled
- tls_insecure
- route_by_latency
- route_randomly

### Cluster mode

Connect to a Redis Cluster by specifying a flag before the main configuration block or by configuring more than one Redis host / address:
```
{
    storage redis cluster {
        address {
            redis-cluster-001.example.com:6379
            redis-cluster-002.example.com:6379
            redis-cluster-003.example.com:6379
        }
    }
}
```

It is also possible to configure the cluster by specifying a single configuration endpoint:
```
{
    storage redis cluster {
        address clustercfg.redis-cluster.example.com:6379
    }
}
```

Parameters `address`, `host`, and `port` all accept either single or multiple input values. A cluster of Redis servers all listening on the same port can be configured simply:
```
{
    storage redis cluster {
        host {
            redis-cluster-001.example.com
            redis-cluster-002.example.com
            redis-cluster-003.example.com
        }
        port 6379
        route_by_latency false
        route_randomly false
    }
}
```
Two optional boolean cluster parameters `route_by_latency` and `route_randomly` are supported.  Either option can be enabled by setting the value to `true` (Default is false)

### Failover mode (Sentinel)

Connecting to Redis servers managed by Sentinel requires both the `failover` flag and `master_name` value to be set:
```
{
    storage redis failover {
        address {
            redis-sentinal-001.example.com:26379
            redis-sentinal-002.example.com:26379
            redis-sentinal-003.example.com:26379
        }
        master_name redis-master-server
    }
}
```
Failover mode also supports the `route_by_latency` and `route_randomly` cluster configuration parameters.

Optionally, if your Sentinel servers require authentication, you can specify the `sentinel_password` parameter.

### Enabling TLS

TLS connections to the Redis server is disabled by default. Since v1.7 certificate verification is enabled by default and will use the system trust store to validate the Redis server certificate (Prior to v1.7 certificate verification was disabled by default).  For instances where TLS is required but the Redis server does not have a verifiable certificate, use the following configuration:
```
{
    storage redis {
        host 127.0.0.01
        port 6379
        tls_enabled true
        tls_insecure true
    }
}
```
You can also use the `tls_server_certs_pem` option to provide one or more PEM encoded certificates to trust:
```
{
    storage redis {
        host 127.0.0.01
        port 6379
        tls_enabled true
        tls_insecure false
        tls_server_certs_pem <<CERTIFICATES
        -----BEGIN CERTIFICATE-----
        MIIDnTCCAoWgAwIBAgIBADANBgkqhkiG9w0BAQsFADCBhTEtMCsGA1UELhMkMzZk
        MWE2MjgtNGZjNi00ZTRkLWJiNDMtZDhlMGNhN2I1OTRiMTEwLwYDVQQDEyhHb29n
        bGUgQ2xvdWQgTWVtb3J5c3RvcmUgUmVkaXMgU2VydmVyIENBMRQwEgYDVQQKEwtH
        b29nbGUsIEluYzELMAkGA1UEBhMCVVMwHhcNMjMxMjE1MjM0MDMyWhcNMzMxMjEy
        MjM0MTMyWjCBhTEtMCsGA1UELhMkMzZkMWE2MjgtNGZjNi00ZTRkLWJiNDMtZDhl
        MGNhN2I1OTRiMTEwLwYDVQQDEyhHb29nbGUgQ2xvdWQgTWVtb3J5c3RvcmUgUmVk
        aXMgU2VydmVyIENBMRQwEgYDVQQKEwtHb29nbGUsIEluYzELMAkGA1UEBhMCVVMw
        ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCF54WBXJ8kTAj7e843XriG
        oXntUoQBP+TdmzBdgW/t9xqi9di7I6zbyl86x+aOENU8xgHQZQxQ/uE0cnJeaMuH
        H7smyiSn77IP+JL3icDk8a8QIJxYmv3ze47a5ZbfJ4VPXYk0Kh/1HXMDMguS2e+a
        PdjhCVZSB1rwgaH6nAIjmoJxdKSiNolm4xeuZPXwzvsuZZXhc+HIOiZMhckxnZfD
        tZsSYZhg0TgswG1DWP+Nq79Z8SSb+uXHPdOEI2w1YKpcZyh5WuGcarMswRh8E3Kf
        UC+9JLot5NBZ+oAKqcQ7R55Wxd+8CI0paPqaccbJgXMIA2pSEhiqNMEYSA/9QtV3
        AgMBAAGjFjAUMBIGA1UdEwEB/wQIMAYBAf8CAQAwDQYJKoZIhvcNAQELBQADggEB
        ABO7LLHzvGkz/IMAEkEyJlQAOrKZD5qC4jTuICQqm9xV17Ql2SLEdKZzAFrEDLJR
        by0dWrPconQG7XqLgb22RceBVKzEGsmObI7LZQLo69MUYI4TcRDgAXeng34yUBRo
        njv+WFAQWNUym4WhUeRceyyOWmzhlC0/zOJPufmVBk6QNmjTfXG2ISCeZhFM0rEb
        C8amwlD9V3EXFjTAEoYs+9Uv1iYDjlMtMrygrrCFTe61Kcgtzp1jsIjfYmTCyt5S
        WVCmGu+wdiPFL9/N0peb5/ORGrdEg4n+a+gCHV9LGVfUcFCyfR42+4FunKwE/OMl
        PaAxpc/KB4nwPitpbsWL8Nw=
        -----END CERTIFICATE-----
        -----BEGIN CERTIFICATE-----
        <another certificate here>
        -----END CERTIFICATE-----
        CERTIFICATES
    }
}
```
If you prefer not to put certificates in your Caddyfile, you can also put the series of PEM certificates into a file and use `tls_server_certs_path` to point Caddy at it.

### Changing the encryption key

`encryption_key` encrypts every value written. `decryption_keys` is an ordered list of additional keys that are tried, in order, when a value does not authenticate with `encryption_key`. Writes always use `encryption_key`. Each entry supports placeholders and must expand to at least 32 bytes (longer values are truncated to 32, as for `encryption_key`). An entry that expands to less, including an unset `{env.*}` placeholder, fails provisioning. `decryption_keys` requires `encryption_key`.

```
{
    storage redis {
        encryption_key  "{env.NEW_KEY}"
        decryption_keys "{env.OLD_KEY}"   # several keys: on one line, or a block with one key per line
    }
}
```

When several servers share the storage and pick up a config change at different times, change a key in phases, and finish each phase on every server before starting the next:

1. `encryption_key OLD`, `decryption_keys NEW`: still writes with the old key, reads both.
2. `encryption_key NEW`, `decryption_keys OLD`: writes with the new key, reads both.
3. Re-encrypt the remaining old-key values (outside this module).
4. `encryption_key NEW` only.

### Connection names

`client_name` sets the connection name (`CLIENT SETNAME`) on every connection, so `CLIENT LIST` shows which server each connection belongs to. It supports placeholders, for example `"{env.FLY_APP_NAME}/{env.FLY_MACHINE_ID}"`, and must be printable ASCII without spaces. With ACLs the user needs `+client|setname`, or every connection fails.

### Access control (ACL) rules

With a Redis 7.2+ or Valkey ACL user per key prefix, the module needs only the commands below. This list holds for `client_type` simple (one `address`) with a single-segment `key_prefix` (no `/`):

- Cluster and failover clients send more commands (cluster topology and Sentinel commands, for example).
- With a multi-segment prefix such as `a/b`, `Store` also adds entries to the directory index of every parent (`ZADD a`), which falls outside `~a/b ~a/b/*`.

| Commands | Used by |
|---|---|
| `select` | connection handshake when `db` is not 0 |
| `client\|setname` | connection handshake when `client_name` is set |
| `client\|setinfo` | connection handshake (a denial is ignored, but is written to `ACL LOG`) |
| `ping` | provisioning |
| `get set del exists zadd zrem zrange` | storage operations |
| `evalsha eval getrange pexpire` | locks (`set get del` are also called inside the lock scripts) |

The key patterns must cover the bare prefix (the root directory index) and everything below it, for example `~caddy_prefix ~caddy_prefix/*`. A single `~caddy_prefix*` would also match other prefixes that start the same way.

```
ACL SETUSER caddy_node reset on >password resetchannels ~caddy_prefix ~caddy_prefix/* -@all \
  +select +client|setname +client|setinfo +ping +get +set +del +exists +zadd +zrem +zrange \
  +evalsha +eval +getrange +pexpire
```

Notes:

- `reset` first, so rules left from an earlier `ACL SETUSER` for the same user do not survive.
- `CLIENT SETINFO` was added in Redis 7.2. On older servers `+client|setinfo` is an unknown subcommand and the whole `ACL SETUSER` fails, so leave it out there.
- `caddy redis repair` also needs `scan` and `type`. `SCAN` returns every key name in the database, whatever the key patterns allow, so never grant it to a user that shares the server with other tenants. Run repair as a separate administrative user.
- go-redis also sends `CLIENT MAINT_NOTIFICATIONS` once per client. Valkey and older Redis do not know that subcommand, so each client adds one `errorstat_ERR` to `INFO errorstats`. This is not an ACL denial and never reaches `ACL LOG`, and it cannot be granted in advance.

`valkey_acl_integration_test.go` checks this list against a Docker Valkey 9.1 server (`APX_VALKEY_ACL_INTEGRATION=1 go test -run TestValkeyACL -v .`).

## Maintenance

This module has been architected to maintain a hierarchical index of storage items using Redis Sorted Sets to optimize directory listing operations typically used by Caddy.  It is possible for this index structure to become corrupted in the event of an unexpected system crash or loss of power.  If you suspect your Caddy storage has been corrupted, it is possible to repair this index structure from the command line by issuing the following command:

```
caddy redis repair --config /path/to/Caddyfile
```

Note that the config parameter is optional (but recommended); if not specified Caddy look for a configuration file named "Caddyfile" in the current working directory.
