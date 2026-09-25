# Performance

"Faster than Vaultwarden" is one of the reasons this server exists, so it is measured, with the
numbers here and a weekly run in CI (`.github/workflows/bench.yml`, results in the run summary).

## How it is measured

`uwulock-bench` sends one kind of request from a number of workers as fast as they can for a
while, after a second of warming up, and reports requests per second and latencies. It knows
nothing about UwULock Server, so pointed at Vaultwarden it measures that the same way. Both run on
the same machine, one after the other, both on the host network (Docker's port forwarding would
cost Vaultwarden time that is not its own).

```bash
cargo build --release -p uwulock-server -p uwulock-bench
UWULOCK_DATA=/tmp/uwulock UWULOCK_LISTEN=127.0.0.1:18443 UWULOCK_UPDATE_CHECK=off \
  ./target/release/uwulock-server &
docker run -d --name vaultwarden --network host -e ROCKET_ADDRESS=127.0.0.1 -e ROCKET_PORT=18080 \
  -v vaultwarden-bench:/data vaultwarden/server:1.37.3
./target/release/uwulock-bench --target http://127.0.0.1:18443 --label "UwULock Server"
./target/release/uwulock-bench --target http://127.0.0.1:18080 --label "Vaultwarden"
```

## Numbers

### 0.0.1 — `/alive`

What the server costs before it does any work: HTTP, routing, middleware. 32 requests in flight,
8 seconds each, a shared 8-core Linux machine with other work on it, so single runs vary a lot;
two runs each:

| Server | Requests/s | p50 | p99 | Memory while idle |
| --- | ---: | ---: | ---: | ---: |
| UwULock Server 0.0.1 | 39,000 – 57,500 | 0.50 – 0.72 ms | 1.5 – 2.5 ms | 12.8 MiB |
| Vaultwarden 1.37.3 | 30,300 – 38,600 | 0.73 – 0.88 ms | 2.5 – 3.9 ms | 38.9 MiB |

This is the floor, not the point: `/alive` does nothing either server could do much better. The
difference that matters is in the requests clients send all the time — sync, revision date,
login — and those come with 0.1, together with their scenarios here.
