# Dogebox Gateway Deployment Guide for libdogecoin REST API

## Overview

The libdogecoin REST API (exposed by `spvnode -u`) is designed to run as a
**localhost-only service** behind a local gateway. [Dogebox](https://dogecoin.org/)
is the recommended gateway for production deployments.

## Architecture

```
Internet → [Dogebox Gateway] → 127.0.0.1:port → [spvnode REST API]
              ↓
         TLS termination
         Authentication
         Rate limiting
         Request filtering
```

1. **`spvnode`** binds its REST API to `127.0.0.1:<port>` (localhost only).
2. **Dogebox** runs on the same host, listening on the public/private interface.
3. Dogebox proxies authorized requests to the localhost spvnode endpoint.
4. Dogebox handles TLS, session management, rate limiting, and access control.

## Starting the REST API

```bash
# Recommended: localhost-only (default for Dogebox deployments)
./spvnode -u 127.0.0.1:8080 scan

# Optional: set API key for defense-in-depth behind Dogebox
export DOGECOIN_API_KEY="your-secret-key"
./spvnode -u 127.0.0.1:8080 scan
```

## Non-Localhost Binding (Not Recommended)

If you must bind to a non-localhost address (e.g., for testing), you **must**
set the `DOGECOIN_API_KEY` environment variable. The server will refuse to
start without it (see mitigation M23):

```bash
export DOGECOIN_API_KEY="your-secret-key"
./spvnode -u 0.0.0.0:8080 scan
# WARNING printed: API key authentication is active
```

Without the API key, the server will exit with an error:

```
ERROR: HTTP API binding to non-localhost address '0.0.0.0' requires
DOGECOIN_API_KEY to be set. Refusing to start without authentication.
```

## Available Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/getBalance` | GET | Total wallet balance |
| `/getAddresses` | GET | All wallet addresses |
| `/getUTXOs` | GET | Unspent transaction outputs |
| `/getTransactions` | GET | Spent transactions |
| `/getWallet` | GET | Download wallet file (binary) |
| `/getHeaders` | GET | Download headers file |
| `/getChaintip` | GET | Current chain tip height |
| `/getTimestamp` | GET | Chain tip timestamp |
| `/getLastBlockInfo` | GET | Latest block information |
| `/getRawTx?txid=<hex>` | GET | Raw transaction by ID |
| `/viewTx?txid=<hex>&vout=<n>` | GET | Transaction output details |
| `/stats?secs=<N>` | GET | On-chain activity summary |
| `/chainStats` | GET | Session chain statistics |

## Security Controls

| Control | Description | Mitigation |
|---------|-------------|-----------|
| API key authentication | `X-API-Key` header checked against `DOGECOIN_API_KEY` env var | M1 |
| Localhost default | Non-localhost binding requires API key | M23 |
| Binding warning | stderr warning on non-localhost bind | M11 |
| Dogebox gateway | TLS, rate limiting, session management | External |

## Security Recommendations

1. **Always use Dogebox** (or equivalent reverse proxy) for production deployments.
2. **Set `DOGECOIN_API_KEY`** even behind Dogebox for defense-in-depth.
3. **Never bind to `0.0.0.0`** without a gateway providing TLS.
4. **Monitor stderr** for security warnings from the spvnode process.
5. **Restrict wallet file access** — wallet files are created with `chmod 0600` (M21).
