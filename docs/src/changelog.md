```@meta
CurrentModule = LibSSH
```

# Changelog

This documents notable changes in LibSSH.jl. The format is based on [Keep a
Changelog](https://keepachangelog.com).

## Unreleased

### Added

- It's possible to set an interface for the [`Forwarder`](@ref) socket to listen
  on with the `localinterface` argument ([#6]).
- A new `Gssapi` module to help with [GSSAPI support](@ref). In particular,
  [`Gssapi.principal_name()`](@ref) was added to get the name of the default
  principal if one is available ([#6]).

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
