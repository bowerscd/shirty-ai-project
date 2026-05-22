# Command-Line Help for `yggdrasil`

This document contains the help content for the `yggdrasil` command-line program.

**Command Overview:**

* [`yggdrasil`↴](#yggdrasil)
* [`yggdrasil run`↴](#yggdrasil-run)
* [`yggdrasil version`↴](#yggdrasil-version)
* [`yggdrasil completions`↴](#yggdrasil-completions)

## `yggdrasil`

High-performance TCP/UDP reverse proxy for residential upstreams

**Usage:** `yggdrasil [OPTIONS] <COMMAND>`

###### **Subcommands:**

* `run` — Run the proxy server
* `version` — Print the build version
* `completions` — Print a shell-completion script for `yggdrasil` to stdout

###### **Options:**

* `--log-format <LOG_FORMAT>` — Output format for structured logs

  Default value: `json`

  Possible values:
  - `json`:
    One JSON object per line (suitable for journald, ELK, Loki, etc.)
  - `pretty`:
    Human-readable single-line format with ANSI colour (suitable for terminals)




## `yggdrasil run`

Run the proxy server

**Usage:** `yggdrasil run [OPTIONS]`

###### **Options:**

* `--config <CONFIG>` — Path to the server configuration file

  Default value: `/etc/yggdrasil/config.toml`
* `--rules-dir <RULES_DIR>` — Override the rules directory specified in the config file
* `--require-mode <REQUIRE_MODE>` — Assert the config resolves to this derived mode and fail fast if not

  Possible values: `gateway`, `relay`, `terminal`

* `--bind <IP>` — Hard-override every rule's `listen` IP with this address. The rule's port is preserved; only the IP is replaced. Overrides `[server].default_bind`



## `yggdrasil version`

Print the build version

**Usage:** `yggdrasil version`



## `yggdrasil completions`

Print a shell-completion script for `yggdrasil` to stdout

**Usage:** `yggdrasil completions <SHELL>`

###### **Arguments:**

* `<SHELL>` — Target shell. The completion script is printed to stdout

  Possible values: `bash`, `elvish`, `fish`, `powershell`, `zsh`




<hr/>

<small><i>
    This document was generated automatically by
    <a href="https://crates.io/crates/clap-markdown"><code>clap-markdown</code></a>.
</i></small>
