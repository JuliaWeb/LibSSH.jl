```@meta
CurrentModule = LibSSH
```

# Server support

*The symbols documented on this page are intended to be safe. They may throw
exceptions but they should never cause memory corruptions or segfaults if used
correctly.*

```@contents
Pages = ["server_support.md"]
Depth = 10
```

---

```@docs
RequestType
```

## SSH Binds

The main type you care about for writing a server is the [`Bind`](@ref), which
is somewhat analogous to a listening socket. It can be bound to a port and when
a connection is attempted by a client it can be accepted with
[`lib.ssh_bind_accept()`](@ref). Implementing everything else (including
authentication) must be done yourself.

If you're writing a server and want to implement keyboard-interactive
authentication, also see [`message_auth_interactive_request`](@ref).

!!! info
    There are some examples of using libssh's C API to write a server
    [here](https://gitlab.com/libssh/libssh-mirror/-/blob/master/examples/samplesshd-cb.c)
    (using callbacks), and another one demonstrating keyboard-interactive
    authentication
    [here](https://gitlab.com/libssh/libssh-mirror/-/blob/master/examples/samplesshd-kbdint.c)
    (not using callbacks). You can also check the source for the [Demo server](@ref).

```@docs
Bind
listen
wait_for_listener
handle_key_exchange
set_auth_methods(::Session, ::Vector{AuthMethod})
set_auth_methods(::lib.ssh_message, ::Vector{AuthMethod})
Callbacks.ServerCallbacks
Callbacks.ServerCallbacks()
set_server_callbacks
set_message_callback
get_error(::Bind)
Base.close(::Bind)
Base.lock(::Bind)
Base.unlock(::Bind)
Base.isopen(::Bind)
```

---

Each [`Session`](@ref) accepted by a [`Bind`](@ref) must be polled for all the
handlers to execute. This is possible through the [`SessionEvent`](@ref) type.

```@docs
SessionEvent
SessionEvent(::Session)
event_dopoll
Base.isassigned(::SessionEvent)
Base.close(::SessionEvent)
```

## Demo server

The `DemoServer` is an extremely simple and limited implementation of an SSH
server using the libssh [server
API](https://api.libssh.org/stable/group__libssh__server.html). It's sole reason
for existence is to be used in test suites to test client code. Do **not**
expose this publicly! See the constructors docstrings for examples of how to use
it (the LibSSH.jl test suite may also be informative).

Supported features:
- Password authentication: only the password is checked, not the username.
- Keyboard-interactive authentication: the server will give two prompts for a
  `Password:` and `Token:` and expect `foo` and `bar` as answers, respectively.
- Command execution: note that requested environment variables from the client
  are currently ignored, and the command output will only be sent back to the
  client after the command has finished.
- Direct port forwarding

Unsupported features (that may be implemented in the future):
- Public key authentication
- GSSAPI authentication
- Reverse port forwarding

One might ask the question, why use a demo server for testing instead of
something battle-hardened like `sshd`? Well, turns out that it's impossible to
run `sshd` as a non-root user unless you disable password authentication
(because `sshd` needs to read `/etc/passwd`), which is definitely something we
want to test. Plus, having a custom server makes it simpler to set up in just
the way we want.

```@autodocs
Modules = [LibSSH.Demo]
```
