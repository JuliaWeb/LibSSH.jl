# Changelog

This documents notable changes in LibSSH.jl. The format is based on [Keep a
Changelog](https://keepachangelog.com).

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
