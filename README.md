# 🗳 Veto

A lightweight, log files based IP blocker with focus on simplicity and speed.

⚠️ Warning ⚠️ : This project is still in a very early stage. Expect things to break or not work
right from time to time. The configuration structure may change any time.

## Build

Have the latest `rustup`, `rust` toolchain and `cargo` installed and run:

```sh
cargo build
```

## Install

Just put the file wherever you like and make sure it's reachable by your `PATH` variable so you can
call it from the CLI everywhere. For example `/usr/local/bin/` is a good place.

- The configuration file is expected at `/etc/veto/config.toml` and required for Veto to work.
- All state related data is saved at `/var/lib/veto/`.

To run Veto as a service copy the [service file](debian/veto.service) to the appropriate location
for your system and enable it in systemd.

A deb package can be found in the release section for easy installation on Debian based systems.

## Configuration

Veto uses a single configuration file to read all settings and blocking rules. The config is
written in the TOML format and furher described in [CONFIGURATION.md](CONFIGURATION.md).

## License

This project is licensed under the [AGPL-3.0 License](LICENSE) (or
<https://www.gnu.org/licenses/agpl-3.0.html>).
