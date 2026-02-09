# AppleJPEGDriver startDecoder() timeout UAF (deferred panic)

By [@zeroxjf](https://x.com/zeroxjf)

**This will kernel panic your device. Save your work.**

Tested on iOS 26.3 (23D125) on iPhone16,2 (A18).

## Trigger

The driver keeps per-codec FIFO queues as vectors of pointers to an embedded node (`node_ptr = req + 0x78`).
On the sync/error path, the dispatch handler frees `req` but does not remove `node_ptr` from the vector.
Later, a queue walk in `fullSpeedRequestExist()` dereferences `*(node_ptr + 8)` (the `req` self-pointer at `req+0x80`)
and hits an MTE tag check fault.

The panic is often deferred: the PoC leaves the driver in a bad state; then opening the Camera app triggers a sync
JPEG decode that times out, creates the stale entry, and the next `finish_io_gated()` call walks the vector and faults.

```
PoC app (tap button):                       Later (open Camera):
  IOServiceOpen("AppleJPEGDriver")            startDecoder(sync)
  submit startDecoder(async) x N                -> queue_io_gated(enqueue node_ptr=req+0x78)
  IOServiceClose(conn)                         -> wait 10s -> timeout -> returns error
    (leaves driver state bad)                  -> startDecoder frees req
                                                 BUG: node_ptr still in vector

Interrupt path:
  finish_io_gated()
    if (driver_flag) fullSpeedRequestExist()
      node_ptr = vector[i]
      req2 = *(node_ptr + 8)   // UAF read of freed req+0x80 -> MTE fault -> panic
```

## Build & Run

1. Open `ios-app/Test.xcodeproj` in Xcode
2. Select your iOS device (simulator is not useful)
3. Build and run
4. Tap the **Panic** button
5. Open the **Camera** app to trigger the deferred panic

