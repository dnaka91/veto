# Veto configuration

The following describes all settings that are understood by Veto.

## `whitelist`

The whitelist contains a list of IP networks (like `192.168.1.0/24`) that will never be blocked.
This is especially useful to keep yourself from being locked out from your own servers while you do
some tests that may trigger the blocking rules.

Example:

```toml
whitelist = ["127.0.0.1/32", "192.168.1.0/24"]
```

## `ipset`

Settings specific to the `ipset` firewall.

### `target`

- `Drop`
- `Reject`
- `Tarpit`

## `rules.<name>`

Rules are the definitions of a files that should be watched, filters applied on the log entries and
all other important settings to these. Each rule must be uniquely named, for example `[rules.web]`.

A full example can be found at the bottom of this document.

### `file`

The file that Veto should watch for changes. It will open this file on startup, read all the
content line by line and process it, blocking anything that matches the filters on the way.

After that it moves to a watching mode where it will get notifications from the OS whenever a change
is made to the file and processes all new lines.

```toml
file = "/etc/log/app.log"
```

### `filters`

The filters are the main part of detecting malicious access. They're **RegEx** rules that match
against a single line from a log file and extract information. They can (and partially must) contain
some special placeholders.

Placeholders are set as `<NAME>` and are replaced with a partial regex rule while parsing the regex
itself. The existing placeholders are as follows:

- `<HOST>` catches the client IP and can be either IPv4 or IPv6. (**Required**)
- `<TIME>` catches the time of the request like `17/Jul/2020:04:02:12 +0000`.
- `<METHOD>` catches the request method like `GET` or `POST`.

```toml
filters = [
    '^<HOST> - - \[<TIME>\] "GET'
]
```

### `ports`

⚠️ Currently not working but it's on the todo list.

```toml
ports = [80, 443]
```

### `timeout`

The timeout defines how long an IP should be put on the blocklist. This also plays a role when
restarting **Veto** as it will remove all IP blocks on shutdown and put all IP back on the blocklist
during startup as long as they're still within the timeout time.

```toml
timeout = "3d"
```

### `rules.<name>.blacklists`

The blacklists of a rule extend the [filters](#filters) but are optional. If no blacklists are
defined, then a matching filter is enough for an IP to be put on the blocklist.

If one or more blacklists are defined, then the extractred data from a filter is further matched
against the words within a blacklist. The name of the blacklist must match the group name of the
filter regex.

For example: You have a filter with a regex match group to get the path of an HTTP request like
`"(P?<path>.*)"` and a blacklist like `path = ["php"]`. The extracted path is checked to contain
the word `php` and if it does the IP will be blocked, otherwise not.

_All words in a blacklist are checked case-insensitive._

```toml
[rules.blacklists]
path = [".aspx", "php"]
ua = ["scraper"]
```

## Full example

The following is a more complex example of a full configuration.

It whitelists an IP network to never block requests from all IPs that fall within and watches a
single log file. Several details are extracted and checked against common paths that are not used
by the web services and common bot names.

```toml
whitelist = ["192.168.1.0/24"]

[rules.web]
file = "/etc/logs/access.log"
filters = [
    '^<HOST> - - \[<TIME>\] "<METHOD> (?P<path>/.*) HTTP/\d\.\d" [3-4]\d{2} \d+ "(?P<ref>[^"]+)" "(?P<ua>[^"]+)"',
]
timeout = "3d"

[rules.web.blacklists]
path = [".aspx", ".env", "cgi-bin", "php"]
ua = [
    "dotbot",
    "go-http",
    "googlebot",
    "goscraper",
    "masscan",
    "netcraft",
    "netsystemsresearch",
    "nimbostratus",
    "zgrab",
]
```
