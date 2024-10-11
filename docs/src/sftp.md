```@meta
CurrentModule = LibSSH
```

# SFTP

A subset of the [SFTP
API](https://api.libssh.org/stable/group__libssh__sftp.html) is wrapped and
available in LibSSH.jl. See the [SFTP example](examples.md#SFTP) for an example
of basic usage.

!!! warning
    When it comes to handling paths, the library currently assumes that the
    server is running on a *NIX system. Some functions will not work when
    connecting to a Windows server.

Unlike the rest of the API, the SFTP C functions are blocking and only work with
blocking [`Session`](@ref)'s. This means that the library has to lock the
session while calling them and no other operations (blocking or unblocking) can
occur while they're being called. In practice this restriction may not be too
onerous since most calls shouldn't take long anyway, and the read/write
implementations use SFTP's asynchronous IO API so they shouldn't block for
long. If it's critical that SFTP operations don't interfere with other
operations (e.g. port forwarding) a workaround would be to open a separate
[`Session`](@ref) for SFTP.

Note that we call all blocking C functions using `@threadcall` so that they
don't block the scheduler, hence as a programmer you don't need to worry about
them hogging a whole thread until they complete.

```@contents
Pages = ["sftp.md"]
Depth = 3
```

## SftpSession
```@docs
SftpSession
SftpSession(::Session)
SftpSession(::Function)
Base.close(::SftpSession)
Base.isopen(::SftpSession)
Base.lock(::SftpSession)
Base.unlock(::SftpSession)
Base.readdir(::AbstractString, ::SftpSession)
Base.rm(::AbstractString, ::SftpSession)
Base.mkdir(::AbstractString, ::SftpSession)
Base.mv(::AbstractString, ::AbstractString, ::SftpSession)
Base.stat(::String, ::SftpSession)
get_extensions(::SftpSession)
get_limits(::SftpSession)
get_error(::SftpSession)
```

## SftpFile
```@docs
SftpFile
Base.open(::String, ::SftpSession)
Base.open(::Function, ::String, ::SftpSession)
Base.close(::SftpFile)
Base.read(::SftpFile)
Base.read(::SftpFile, ::Type{String})
Base.read!(::SftpFile, ::Vector{UInt8})
Base.write(::SftpFile, ::DenseVector)
Base.write(::SftpFile, ::AbstractString)

Base.isopen(::SftpFile)
Base.isreadable(::SftpFile)
Base.isreadonly(::SftpFile)
Base.iswritable(::SftpFile)
Base.position(::SftpFile)
Base.seek(::SftpFile, ::Integer)
Base.seekstart(::SftpFile)
Base.seekend(::SftpFile)
```

## File type helpers

```@docs
Base.ispath(::AbstractString, ::SftpSession)
Base.ispath(::SftpAttributes)
Base.isdir(::AbstractString, ::SftpSession)
Base.isdir(::SftpAttributes)
Base.isfile(::AbstractString, ::SftpSession)
Base.isfile(::SftpAttributes)
Base.issocket(::AbstractString, ::SftpSession)
Base.issocket(::SftpAttributes)
Base.islink(::AbstractString, ::SftpSession)
Base.islink(::SftpAttributes)
Base.isblockdev(::AbstractString, ::SftpSession)
Base.isblockdev(::SftpAttributes)
Base.ischardev(::AbstractString, ::SftpSession)
Base.ischardev(::SftpAttributes)
Base.isfifo(::AbstractString, ::SftpSession)
Base.isfifo(::SftpAttributes)
```

## Other types
```@docs
SftpAttributes
SftpError
SftpException
```

When an [`SftpException`](@ref) is printed it will be displayed like this:
```@repl
import LibSSH as ssh
ssh.SftpException("Failure", "/tmp/foo", ssh.SftpError_GenericFailure, "SFTP failed", "foo@bar")
```

Note that the SFTP subsystem doesn't always set an error on the
[`Session`](@ref), so take the `Session error` with a grain of salt.
