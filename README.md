# webhookd

A simple gitlab web hooks daemon. Run scripts whenever hook is triggered.

## Installation

There are two ways:
1. Run `cargo install webhookd` to install webhookd.
2. Install `cargo-deb` first, then run `cargo deb --install`.

## Configuration

See `example.toml` for usage.

## Usage

Run:

```bash
> RUST_LOG=info webhookd --config config.toml
```
