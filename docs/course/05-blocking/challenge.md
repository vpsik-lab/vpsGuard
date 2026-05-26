# Challenge: Blocking

---

## ⭐ Level 1: Trace the Flow

Write down the exact call chain from `main.go` when an event arrives:
1. Which function receives the event from the bus?
2. How does it call the scorer?
3. How does it call the decision engine?
4. How does it call `BlockIP`?

**Hint:** Look at `processEvent()` in `cmd/vpsGuard/main.go`.

---

## ⭐⭐ Level 2: Add a Custom Threshold

Add a `block_min_duration_hours` field to `ScoringConfig` that sets a minimum block time even for low-scoring IPs.

**Hint:** Modify `decision.go` and add validation in `config.go`.

---

## ⭐⭐⭐ Level 3: Geo-Blocking

Implement a `--geo-block <country>` CLI flag that adds entire country IP ranges to the nftables set. Use `ipinfo.io` or MaxMind GeoLite2 data.

**Hint:** You'll need to download CIDR ranges, convert to nftables elements, and add them in a batch.

---

## Solution

<details>
<summary>Click for Level 1 solution</summary>

1. The event loop in `main.go` receives from `eventCh`
2. Calls `processEvent()` with the event
3. Inside: `scorer.RecordEvent(evt)`, then `scorer.Evaluate(ctx, evt, intelClient)` 
4. `decision.Evaluate(ctx, evt, scoreResult, rulesEngine)` returns actions
5. For each action with `Block: true`: `fw.BlockIP(ctx, ip, action.Duration)`

The exact code is at `cmd/vpsGuard/main.go` in the `processEvent` function.
</details>
