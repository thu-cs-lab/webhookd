# webhookd

A simple gitlab web hooks daemon. Run scripts whenever hook is triggered.

## Installation

Run `cargo install webhookd` to install webhookd.

## Configuration

See `example.toml` for usage.

## Usage

Run:

```bash
> RUST_LOG=info webhookd --config config.toml
```
