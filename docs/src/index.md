# LibSSH.jl

This package provides a high-level API and low-level bindings to
[libssh](https://libssh.org). You can use it to programmatically create an SSH
connection to a remote server and do things like:

- Execute remote commands
- Set up port forwarding
- Create security holes (better be careful lol)

The upstream libssh library has implementations for both a client and server,
but this package (currently) only attempts to provide a high-level client API. A
demo SSH server is available, but it's only intended to be used for tests.

These docs were generated against this upstream libssh version:
```@repl
import LibSSH as ssh
ssh.lib_version()
```

!!! warning
    LibSSH.jl is still under heavy development and may contain bugs. We strongly
    recommend testing your code as much as possible. If you have found a bug,
    please [report it](https://github.com/JamesWrigley/LibSSH.jl/issues/new).

## Installation

LibSSH.jl isn't registered yet, so for now you'll have to add it from Github:
```julia-repl
pkg> add https://github.com/JamesWrigley/LibSSH.jl
```

## Limitations

- GSSAPI support is disabled on Windows and macOS due to `Kerberos_krb5_jll` not
  being available on those platforms.
- Many features don't have high-level wrappers (see [Contributing](@ref)).

## FAQ

#### Can I use this to create an SSH server?

Technically yes, but you almost certainly *shouldn't* because authentication and
authorization is proper hard and there's lots of ways it could go wrong.

#### Can I use this to create an SSH client?

Yes. But make sure you test it appropriately with the [Demo server](@ref).

#### Why isn't <beloved-feature> supported in the high-level API?

The author is fabulously lazy and hasn't bothered (but will accept PRs to do
so <3).

## Contents
```@contents
Pages = ["examples.md", "sessions_and_channels.md", "server_support.md", "utilities.md", "bindings.md"]
Depth = 10
```
