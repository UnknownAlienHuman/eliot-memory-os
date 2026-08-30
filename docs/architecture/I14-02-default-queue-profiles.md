## I14.2. Default queue profiles

Initial defaults, tuned after measurement:

| Pool | Items | Concurrency | Behavior under pressure |
|---|---:|---:|---|
| control | reserved | dedicated | never borrowed by normal work |
| interactive | 512 | CPU/latency bounded | BUSY with short retry |
| verification | 512 | separate semaphore | preserve finish/proof |
| canonical writes | 2048 + byte cap | store lanes | durable stage or backpressure |
| background | 1024 | low priority | pause/drop rebuildable work |
| model jobs | policy budget | route-specific | checkpoint/deny |
| swarm work | plan envelope | bounded fan-out | stop admission/replan |
| reports | 128 | low | regenerate later |

Numbers are defaults in `runtime.toml`, not Architecture.

