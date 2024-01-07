# API reference

This documents the high-level API around libssh.

```@contents
Pages = ["api.md"]
Depth = 10
```

---

```@meta
CurrentModule = LibSSH
```

```@docs
AuthMethod
```

## Sessions

An SSH session represents a connection between a client and a remote server. A
session must be authenticated before being able to do anything with it.

!!! info
    Also see the [upstream
    tutorial](https://api.libssh.org/stable/libssh_tutor_guided_tour.html).

```@docs
Session
Session(::Union{AbstractString, Sockets.IPAddr})
Session(::lib.ssh_session)
connect
disconnect
isconnected
userauth_list
userauth_none
userauth_password
userauth_kbdint
userauth_kbdint_getprompts
userauth_kbdint_setanswers
get_error(::Session)
Base.isopen(::Session)
Base.close(::Session)
Base.wait(::Session)
```

## Channels

SSH channels are things you can create on top of a session to actually do things
(like running commands, etc). You can have as many channels on a single session
as you like. Channels have certain types, like an `exec` channel for running
commands, and can only be used to do one thing. e.g. if you want to run two
commands you must create two channels.

!!! info
    The [upstream
    tutorial](https://api.libssh.org/stable/libssh_tutor_shell.html) has more
    information about channels.

```@docs
SshChannel
SshChannel(::Session)
SshChannel(::Function, ::Session)
SshChannel(::lib.ssh_channel, Any)

set_channel_callbacks
channel_send_eof
channel_request_send_exit_status
poll_loop

Base.isassigned(::SshChannel)
Base.isopen(::SshChannel)
Base.close(::SshChannel)
Base.eof(::SshChannel)
Base.iswritable(::SshChannel)
Base.write(::SshChannel, ::AbstractString)
Base.write(::SshChannel, ::Vector{UInt8})
```

### Channel operations

#### Command execution

```@docs
execute
```

#### Direct port forwarding

```@docs
Forwarder
Forwarder(::Session, ::Int, ::String, ::Int)
Forwarder(::Function)
Base.close(::Forwarder)
```

## Server support

If you're writing a server and want to implement keyboard-interactive
authentication, also see [`message_auth_interactive_request`](@ref).

```@docs
Bind
listen
wait_for_listener
handle_key_exchange
set_auth_methods(::Session, ::Vector{AuthMethod})
set_auth_methods(::lib.ssh_message, ::Vector{AuthMethod})
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
handlers to execute. This is possible through the [`SshEvent`](@ref) type.

```@docs
SshEvent
SshEvent()
event_add_session
event_remove_session
event_dopoll
Base.close(::SshEvent)
```

### Demo server

One might ask the question, why use a demo server for testing instead of
something battle-hardened like `sshd`? Well, turns out that it's impossible to
run `sshd` as a non-root user unless you disable password authentication
(because `sshd` needs to read `/etc/passwd`), which is definitely something we
want to test.

Plus, having a custom server makes it simpler to set up in just the way we
want.

```@autodocs
Modules = [LibSSH.Demo]
```

## Messages

```@docs
message_type
message_subtype
message_auth_interactive_request
```

## PKI

```@autodocs
Modules = [LibSSH.PKI]
```
