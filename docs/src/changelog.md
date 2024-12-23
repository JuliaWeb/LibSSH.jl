```@meta
CurrentModule = LibSSH
```

# Changelog

This documents notable changes in LibSSH.jl. The format is based on [Keep a
Changelog](https://keepachangelog.com).

## Unreleased

### Changed
- Made the finalizers for [`Session`](@ref), [`SshChannel`](@ref), and
  [`SftpSession`](@ref) slightly more robust. It's still not recommended to rely
  on them to clean up all resources but in most cases they should be able to do
  so ([#31]).

## [v0.7.1] - 2024-12-06

### Added
- Implemented [`Base.mkpath(::AbstractString, ::SftpSession)`](@ref) ([#30]).
- Added support for 32-bit platforms, though only Linux is tested with that in
  CI ([#29]).

### Fixed
- Fixed behaviour of the [`Session`](@ref)`.known_hosts` property ([#30]).

## [v0.7.0] - 2024-10-25

### Added

- [`Demo.DemoServer`](@ref) now supports passing `allow_auth_none=true` to allow
  easily setting up passwordless authentication ([#28]).

### Fixed

- Previously the [`Demo.DemoServer`](@ref)'s command execution implementation
  would only send the command output after it had finished. Now the output gets
  sent as soon as it's printed by the command ([#28]).

### Changed

- **Breaking**: [`set_channel_callbacks()`](@ref) will remove any existing
  callbacks ([#28]).

## [v0.6.1] - 2024-10-20

### Added

- Added support for setting the file descriptor for a [`Session`](@ref) during
  construction ([#21]).
- Our [`Base.run()`](@ref) methods now accept plain `String`s as well as `Cmd`s
  ([#24]).
- Implemented convenience [`Base.read(::String, ::SftpSession)`](@ref) methods
  that will take a `String` filename without having to open the file explicitly
  ([#25]).
- Added support for specifying whether a [`Session`](@ref) should use the users
  SSH config with the `process_config` option ([#25]).

### Fixed

- Improved handling of possible errors in [`Base.readdir()`](@ref) ([#20]).
- Fixed exception handling for [`Base.run()`](@ref), now it throws a
  [`SshProcessFailedException`](@ref) or [`LibSSHException`](@ref) on command
  failure instead of a plain `TaskFailedException` ([#25]).

## [v0.6.0] - 2024-10-11

### Added

- Implemented [`Base.readchomp(::Cmd)`](@ref) for remote commands ([#12]).
- Add support for passing environment variables to remote commands with
  [`Base.run(::Cmd)`](@ref) ([#12]).
- Made it possible to assign callbacks to [`Callbacks.ServerCallbacks`](@ref) and
  [`Callbacks.ChannelCallbacks`](@ref) by property ([#14]).
- [`close(::SshChannel)`](@ref) and [`closewrite(::SshChannel)`](@ref) now
  support an `allow_fail` argument that will print a warning instead of throw an
  exception if modifying the `lib.ssh_channel` fails ([#16]).
- Initial [SFTP](sftp.md) client support ([#16], [#18], [#19]).

### Fixed

- Fixed segfaults that would occur in [`SshChannel`](@ref) when its
  [`Session`](@ref) is disconnected by the remote end ([#13]).
- Fixed some concurrency bugs in the [`Demo.DemoServer`](@ref) and
  [`SessionEvent`](@ref) ([#15]).
- Fixed a race condition in the [`Demo.DemoServer`](@ref) that could cause
  segfaults ([#16]).

### Changed

- **Breaking**: [`Session`](@ref) now needs to be closed explictly instead of
  relying on the finalizer for the memory to be freed.

## [v0.5.0] - 2024-08-10

### Added

- A new [`Forwarder(::Session, ::String, ::Int)`](@ref) constructor to allow for
  forwarding a port to an internal socket instead of to a port ([#10]).

### Changed

- Updated the libssh library to 0.11.0 ([#11]).

## [v0.4.0] - 2024-03-12

### Added

- A `throw` argument to [`poll_loop()`](@ref) ([#9]).
- Support for some more options in [`Session`](@ref) ([#9]).
- A new method for [`PKI.get_fingerprint_hash(::PKI.SshKey)`](@ref) to get a
  public key fingerprint straight from a [`PKI.SshKey`](@ref) ([#9]).

### Changed

- Some automatically-wrapped low-level functions changed names back to retaining
  their `ssh_` prefixes, and they now have a `throw` argument to allow disabling
  throwing an exception upon error ([#9]).
- [`authenticate()`](@ref) will now do host verification as well. This is
  critical for security so it is *strongly recommend* that all dependencies
  update to this release ([#9]).
- All the `throw_on_*` arguments in the various `Session` and `SshChannel`
  methods have been renamed `throw` for consistency with `Base` and the new
  `throw` arguments in some auto-wrapped bindings ([#9]).

## [v0.3.0] - 2024-03-10

### Added

- It's possible to set an interface for the [`Forwarder`](@ref) socket to listen
  on with the `localinterface` argument ([#6]).
- A new `Gssapi` module to help with [GSSAPI support](@ref). In particular,
  [`Gssapi.principal_name()`](@ref) was added to get the name of the default
  principal if one is available ([#6]).
- An experimental [`authenticate()`](@ref) function to simplify authenticating ([#7]).
- A do-constructor for [`Session(::Function)`](@ref) ([#8]).

### Changed

- The `userauth_*` functions will now throw a `LibSSHException` by default if
  they got a `AuthStatus_Error` from libssh. This can be disabled by passing
  `throw_on_error=false` ([#6]).
- `gssapi_available()` was renamed to [`Gssapi.isavailable()`](@ref) ([#6]).
- [`userauth_kbdint_getprompts()`](@ref) returns a vector of `KbdintPrompt`
  objects instead of tuples ([#7]).

### Fixed

- Fixed some race conditions in [`poll_loop()`](@ref) and [`Forwarder()`](@ref)
  ([#6]).
- [`Base.run(::Cmd, ::Session)`](@ref) now properly converts commands into
  strings before executing them remotely, previously things like quotes weren't
  escaped properly ([#6]).
- Fixed a bug in [`Base.run(::Cmd, ::Session)`](@ref) that would clear the
  output buffer when printing ([#6]).
- Changed [`poll_loop()`](@ref) to poll the stdout and stderr streams, which
  fixes a bug where callbacks would sometimes not get executed even when data
  was available ([#8]).

## [v0.2.1] - 2024-02-27

### Added

- Initial client support for GSSAPI authentication ([#3]). This is not fully
  tested, so use it with caution.

### Changed

- Renamed `channel_send_eof()` to [`closewrite(::SshChannel)`](@ref) ([#4]).

### Fixed

- An exception in [`get_error(::Session)`](@ref) ([#5]).

## [v0.2.0] - 2024-02-01

### Changed

- The [Command execution](@ref) API was completely rewritten to match Julia's
  API ([#2]). This is a breaking change, any code using the old `ssh.execute()`
  will need to be rewritten.

### Fixed

- A cause of segfaults was fixed by storing callbacks properly, so they don't get
  garbage collected accidentally ([#2]).

## [v0.1.0] - 2024-01-29

The initial release 🎉 ✨

### Added

- Basic client support, and high-level wrappers for some [Channel
  operations](@ref).
- A [Demo server](@ref) for testing SSH clients.
