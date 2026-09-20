# DATUM Gateway (FederationCoin)

FederationCoin fork of [OCEAN-xyz/datum_gateway](https://github.com/OCEAN-xyz/datum_gateway) at pin `dbc3b143`. This binary mines **this** chain: talk to `federationcoind` (not Bitcoin Core, not Knots as the product node). GBT must advertise `!blake2b`. Work is header-v2 (164 bytes) hashed with our GetHash (tagged SHA-256 + Blake2b-256, profile 0, null XOR key).

It is not Bitcoin-only. It is not CONVOY. Do not merge or copy CONVOYMining `datum_gateway`. Hashers speak **Stratum only**. This process may speak DATUM to a Prime; WebSocket never does.

The gateway:

- Fetches templates from local `federationcoind` (`getblocktemplate` with `{"rules":["segwit","blake2b"]}`)
- Serves mill-shaped Stratum v1 on TCP (`stratum.listen_addr` / `listen_port`, default loopback `127.0.0.1:23334`)
- Optionally serves the same JSON-RPC over RFC6455 **text** WebSocket on a **dedicated** port (`stratum.ws_listen_addr` / `ws_listen_port`, path `/stratum`; `0` disables). Not port 23334. No Bearer, no admin API, no `client.pool_stats`.
- Submits solved blocks as serialized **164-byte header v2** plus transactions
- For pooled rewards, may connect to a DATUM Prime (`datum.pool_host`; default empty so solo is valid). Dummy MAIN is unused.

Hasher work is the 80-byte `datum_work_header` (prevHidden || nonce8 || ntime8 || work_root), not Bitcoin SHA256d of an 80-byte header.

Diagram: workspace `docs/diagrams/epic-gateway-hasher.puml`.

## Requirements

- 64-bit Linux (other systems may work; you own the risk)
- Synced `federationcoind` (`-testnet` RPC **35332**; cookie `~/.federationcoin/testnet3/.cookie`)
- libcurl, libjansson, libsodium; libmicrohttpd only if you build the dashboard (`ENABLE_API`, still default `api.listen_port` **0**)
- Modest RAM: packaged defaults are mill-sized (not 1024-client Ocean RAM)

Debian/Ubuntu:

    sudo apt install cmake pkgconf libcurl4-openssl-dev libjansson-dev libsodium-dev libmicrohttpd-dev psmisc

Compile:

    cmake . && make
    ./datum_gateway --test

## Configuration

`./datum_gateway --example-conf` prints a template (also `doc/example_datum_gateway_config.json`). Required: `bitcoind.rpcurl` and `mining.pool_address`. Prefer the RPC cookie over a password in git.

Packaged defaults:

- `stratum.listen_addr` `127.0.0.1`
- `api.listen_port` `0` (dashboard off)
- `datum.pool_host` `""` (solo)
- `datum.pooled_mining_only` `false`
- `stratum.ws_listen_port` `0` (WebSocket off)

Point hashers at TCP Stratum or `ws://127.0.0.1:<ws_listen_port>/stratum`. Password `"x"`. extraNonce2 is 8 bytes.

`blocknotify` on a **laptop** `federationcoind` can signal this process so work does not go stale. Packaged `api.listen_port` is 0, so the fallback GBT poll is the normal path. Do not send USR1 at a seed node pod.

See [doc/usernames.md](doc/usernames.md) for stratum usernames.

## License

MIT. See LICENSE. File headers keep the Ocean copyright. This tree is a FederationCoin product fork, not an Ocean, Knots, or CONVOY binary.
