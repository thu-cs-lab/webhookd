# webhookd

A simple GitLab/GitHub web hooks daemon. Run scripts whenever hook is triggered.

## Installation

There are two ways:
1. Run `cargo install webhookd` to install webhookd.
2. Use `cargo-deb`:

```
> cargo install cargo-deb
> git clone https://github.com/jiegec/webhookd.git
> cd webhookd
> cargo deb --separate-debug-symbols --compress-debug-symbols --install
```

## Configuration

See `example.toml` for usage. Then, register this webhook in GitLab/GitHub. Currently only json is supported.

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
Environment="WEBHOOKD_CONFIG=/path/to/config.toml"
```

Then, run `sudo systemctl enable --now webhookd` to activate.

## License

Licensed under GPL-3.0-or-later license.
