# webhookd
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fjiegec%2Fwebhookd.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fjiegec%2Fwebhookd?ref=badge_shield)


A simple GitLab/GitHub web hooks daemon. Run scripts whenever hook is triggered.

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
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fjiegec%2Fwebhookd.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fjiegec%2Fwebhookd?ref=badge_large)