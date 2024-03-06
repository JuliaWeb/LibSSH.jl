```@meta
CurrentModule = LibSSH
```

# Sessions and Channels

*The symbols documented on this page are intended to be safe. They may throw
exceptions but they should never cause memory corruptions or segfaults if used
correctly.*

This documents the high-level API around SSH sessions and channels, which is
almost everything you need to care about to create a SSH client.

```@contents
Pages = ["sessions_and_channels.md"]
Depth = 10
```

---

```@docs
AuthMethod
AuthStatus
LibSSHException
KnownHosts
HostVerificationException
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
is_known_server
get_server_publickey
update_known_hosts
authenticate
authenticate_cli
userauth_list
userauth_none
userauth_password
userauth_kbdint
userauth_kbdint_getprompts
userauth_kbdint_setanswers
userauth_gssapi
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

Callbacks.ChannelCallbacks
Callbacks.ChannelCallbacks()
set_channel_callbacks
channel_request_send_exit_status
poll_loop

Base.isassigned(::SshChannel)
Base.isopen(::SshChannel)
Base.close(::SshChannel)
Base.eof(::SshChannel)
Base.closewrite(::SshChannel)
Base.iswritable(::SshChannel)
Base.write(::SshChannel, ::AbstractString)
Base.write(::SshChannel, ::Vector{UInt8})
```

### Channel operations

You should prefer using these instead of more low-level methods, if you can.

#### Command execution

LibSSH.jl attempts to mimic Julia's API for running local commands with `run()`
etc. But some features are not supported and we attempt to document all of the
differences.

```@docs
SshProcessFailedException
SshProcess
Base.wait(::SshProcess)
Base.success(::SshProcess)
Base.run(::Cmd, ::Session)
Base.read(::Cmd, ::Session)
Base.read(::Cmd, ::Session, ::Type{String})
Base.success(::Cmd, ::Session)
```

#### Direct port forwarding

```@docs
Forwarder
Forwarder(::Session, ::Int, ::String, ::Int)
Forwarder(::Function)
Base.close(::Forwarder)
```
