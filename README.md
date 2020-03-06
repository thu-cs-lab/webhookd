# webhookd

A simple gitlab web hooks daemon. Run scripts whenever hook is triggered.

## Installation

There are two ways:
1. Run `cargo install webhookd` to install webhookd.
2. Use `cargo-deb`:

```
> cargo install cargo-deb
> git clone https://github.com/jiegec/webhookd.git
> cd webhookd
> cargo deb --install
```

## Configuration

See `example.toml` for usage.

## Usage

Run webhookd manually:

```bash
> RUST_LOG=info webhookd --config config.toml
```

Run webhookd in systemd:

```bash
> sudo systemctl edit webhookd
# Add the following lines if needed
[Service]
User=nobody
Group=nobody
Environment=$WEBHOOKD_CONFIG=/path/to/config.toml$
```

Then, run `sudo systemctl enable --now webhookd` to activate.