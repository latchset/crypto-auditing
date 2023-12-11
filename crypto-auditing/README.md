# crypto-auditing

[![crates.io badge](https://img.shields.io/crates/v/crypto-auditing.svg)](https://crates.io/crates/crypto-auditing)

This crate provides a library interface to interact with the
crypto-auditing event broker. To see the whole architecture, see the design [document](https://github.com/latchset/crypto-auditing/blob/main/docs/architecture.md).

To use in your project, add into your `Cargo.toml`:
```toml
[dependencies]
crypto-auditing = "0.2"
```

## Example

The following example connects to the event broker and receives events
prefixed with "tls::".

```rust
use crypto_auditing::event_broker::Client;
use futures::stream::StreamExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = Client::new().scopes(&vec!["tls".to_string()]);

    let (_handle, mut reader) = client.start().await?;

    tokio::spawn(async move {
        while let Some(event) = reader.next().await {
            println!("{:?}", &event);
        }
    });

    tokio::signal::ctrl_c().await?;

    Ok(())
}
```

See [full documentation here](https://docs.rs/crypto-auditing).
