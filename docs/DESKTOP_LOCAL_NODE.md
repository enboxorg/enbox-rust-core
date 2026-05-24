# Desktop Local Node Integration

`dwn_rs_core::desktop` defines the native desktop boundary for running a local DWN without Bun, Node, Electrobun, or a webview-owned process.

## Modes

- Embedded mode keeps the DWN node in the desktop application's Rust process and exposes typed Rust calls through `DesktopLocalNode::process_message`.
- Loopback server mode starts an optional native local service behind `DesktopLocalServer`, advertising HTTP and WebSocket endpoints on loopback only.

The core module provides callback traits and in-memory smoke-test implementations. Production desktop apps should wire `DesktopMessageProcessor` to the real DWN facade, `DesktopLocalServer` to the chosen HTTP/WebSocket server crate, and `DesktopDeliveryQueue` to durable local storage.

## Discovery

Desktop clients discover a loopback node through `DesktopDiscoveryRegistry` records. The advertised shape matches the current `~/.enbox/dwn.json` concept used by the TypeScript Electrobun app:

```json
{
  "endpoint": "http://127.0.0.1:55500",
  "pid": 12345,
  "capabilities": ["http", "ws"]
}
```

Native integrations can publish the same record to `~/.enbox/dwn.json`, an app-group container, or another platform registry. Clients should validate the endpoint with `GET /info` and require the service name `@enbox/dwn-server` before trusting a cached endpoint.

## Forwarding And Delivery

`DesktopDeliveryQueue` is the native boundary for local-first forwarding and `$delivery` work:

- `EndpointForwarding` mirrors forwarding accepted Records writes/deletes to the tenant's other DWN endpoints.
- `ProtocolDelivery` mirrors `$delivery` fan-out to protocol participants.
- `dedup_key` lets implementations suppress forwarding loops like the TypeScript delivery service.

Delivery work is queued separately from `process_message`, so a local desktop node can accept writes quickly and keep retryable forwarding work alive independently of the UI webview.

## Smoke Tests

Run `cargo +1.89.0 test-desktop` to validate the desktop integration skeleton.
