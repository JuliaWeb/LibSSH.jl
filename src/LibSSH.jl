module LibSSH

export SSH_LOG_NOLOG, SSH_LOG_WARNING, SSH_LOG_PROTOCOL, SSH_LOG_PACKET, SSH_LOG_FUNCTIONS

import Sockets
import FileWatching

using DocStringExtensions
using PrecompileTools: @compile_workload

@static if Sys.iswindows()
    # Windows needs its own bindings because some types differ, most importantly
    # socket_t.
    if Sys.WORD_SIZE == 64
        include(joinpath(@__DIR__, "..", "lib", "x86_64-w64-mingw32.jl"))
    else
        include(joinpath(@__DIR__, "..", "lib", "i686-w64-mingw32.jl"))
    end
elseif Sys.WORD_SIZE == 64
    include(joinpath(@__DIR__, "..", "lib", "x86_64-linux-gnu.jl"))
else
    include(joinpath(@__DIR__, "..", "lib", "i686-linux-gnu.jl"))
end

using .lib
import .lib: LibSSHException, SSH_OK, SSH_ERROR, SSH_AGAIN, SSH_EOF


"""
$(TYPEDEF)

Enum for the different authentication methods libssh supports:
- `AuthMethod_Unknown`
- `AuthMethod_None`
- `AuthMethod_Password`
- `AuthMethod_PublicKey`
- `AuthMethod_HostBased`
- `AuthMethod_Interactive`
- `AuthMethod_GSSAPI_MIC`
"""
@enum AuthMethod begin
    AuthMethod_Unknown = SSH_AUTH_METHOD_UNKNOWN
    AuthMethod_None = SSH_AUTH_METHOD_NONE
    AuthMethod_Password = SSH_AUTH_METHOD_PASSWORD
    AuthMethod_PublicKey = SSH_AUTH_METHOD_PUBLICKEY
    AuthMethod_HostBased = SSH_AUTH_METHOD_HOSTBASED
    AuthMethod_Interactive = SSH_AUTH_METHOD_INTERACTIVE
    AuthMethod_GSSAPI_MIC = SSH_AUTH_METHOD_GSSAPI_MIC
end

"""
$(TYPEDEF)

Enum for the possible authentication responses from a server:
- `AuthStatus_Error`
- `AuthStatus_Denied`
- `AuthStatus_Partial`
- `AuthStatus_Success`
- `AuthStatus_Info`
- `AuthStatus_Again`
"""
@enum AuthStatus begin
    AuthStatus_Error = Int(SSH_AUTH_ERROR)
    AuthStatus_Denied = Int(SSH_AUTH_DENIED)
    AuthStatus_Partial = Int(SSH_AUTH_PARTIAL)
    AuthStatus_Success = Int(SSH_AUTH_SUCCESS)
    AuthStatus_Info = Int(SSH_AUTH_INFO)
    AuthStatus_Again = Int(SSH_AUTH_AGAIN)
end

"""
$(TYPEDEF)

Enum for the result of checking a servers public key in the users known hosts
file. See [`is_known_server()`](@ref).

- `KnownHosts_Ok`
- `KnownHosts_Changed`
- `KnownHosts_Other`
- `KnownHosts_Unknown`
- `KnownHosts_NotFound`
- `KnownHosts_Error`
"""
@enum KnownHosts begin
    KnownHosts_Ok = Int(lib.SSH_KNOWN_HOSTS_OK)
    KnownHosts_Changed = Int(lib.SSH_KNOWN_HOSTS_CHANGED)
    KnownHosts_Other = Int(lib.SSH_KNOWN_HOSTS_OTHER)
    KnownHosts_Unknown = Int(lib.SSH_KNOWN_HOSTS_UNKNOWN)
    KnownHosts_NotFound = Int(lib.SSH_KNOWN_HOSTS_NOT_FOUND)
    KnownHosts_Error = Int(lib.SSH_KNOWN_HOSTS_ERROR)
end

"""
$(TYPEDEF)

Enum for the types of SSH requests a client can send to a server:
- `RequestType_Auth`
- `RequestType_ChannelOpen`
- `RequestType_Channel`
- `RequestType_Service`
- `RequestType_Global`
"""
@enum RequestType begin
    RequestType_Auth = Int(lib.SSH_REQUEST_AUTH)
    RequestType_ChannelOpen = Int(lib.SSH_REQUEST_CHANNEL_OPEN)
    RequestType_Channel = Int(lib.SSH_REQUEST_CHANNEL)
    RequestType_Service = Int(lib.SSH_REQUEST_SERVICE)
    RequestType_Global = Int(lib.SSH_REQUEST_GLOBAL)
end

"""
$(TYPEDEF)
$(TYPEDFIELDS)

Represents a failed host verification. See the `status` field for the exact
reason.
"""
struct HostVerificationException <: Exception
    msg::String
    status::KnownHosts
end

"""
$(TYPEDSIGNATURES)

Helper to construct an exception with a generic error message.
"""
function HostVerificationException(status::KnownHosts)
    HostVerificationException("Host verification of server failed", status)
end

"""
$(TYPEDSIGNATURES)

Convert a buffer to a colon-separated hex string. This is identical to
`bytes2hex()`, except that each byte will be separated by a colon.

Wrapper around [`lib.ssh_get_hexa()`](@ref).

## Examples

```jldoctest
julia> import LibSSH as ssh

julia> buffer = collect(UInt8, 1:10);

julia> ssh.get_hexa(buffer)
"01:02:03:04:05:06:07:08:09:0a"

julia> bytes2hex(buffer)
"0102030405060708090a"
```
"""
function get_hexa(buffer::Vector{UInt8})
    ret = lib.ssh_get_hexa(Ptr{Cuchar}(pointer(buffer)), length(buffer))
    if ret == C_NULL
        throw(LibSSHException("Could not convert buffer to hexadecimal string"))
    end

    hex_str = unsafe_string(Ptr{UInt8}(ret))
    lib.ssh_string_free_char(ret)

    return hex_str
end

"""
$(TYPEDSIGNATURES)

Get the version of the libssh library that's used.
"""
function lib_version()
    VersionNumber(lib.LIBSSH_VERSION_MAJOR, lib.LIBSSH_VERSION_MINOR, lib.LIBSSH_VERSION_MICRO)
end

# Safe wrapper around poll_fd(). There's a race condition in older Julia
# versions between the loop condition evaluation and this line, so we wrap
# poll_fd() in a try-catch in case the bind (and thus the file descriptor) has
# been closed in the meantime, which would cause poll_fd() to throw an IOError:
# https://github.com/JuliaLang/julia/pull/52377.
function _safe_poll_fd(args...; kwargs...)
    result = nothing
    try
        result = FileWatching.poll_fd(args...; kwargs...)
    catch ex
        # An ArgumentError means the fd is invalid
        if !(ex isa Base.IOError) && !(ex isa TypeError) && !(ex isa ArgumentError)
            rethrow()
        end
    end

    return result
end

# libssh's socket_t is a file descriptor on POSIX but a Windows SOCKET, which is
# not a CRT fd. Wrapping a SOCKET in RawFD makes FileWatching try to convert it
# with _get_osfhandle() and fail, so Windows uses WindowsRawSocket instead.
# See https://github.com/JuliaWeb/LibSSH.jl/issues/34.
@static if Sys.iswindows()
    const SocketFD = Base.Libc.WindowsRawSocket

    _socketfd(fd::Integer) = Base.Libc.WindowsRawSocket(Ptr{Cvoid}(fd % UInt))

    # dup(2) doesn't work on a SOCKET, the winsock equivalent is
    # WSADuplicateSocketW() into our own process + WSASocketW(). Like dup(2) it
    # returns a second reference to the same socket. Note that DuplicateHandle()
    # (what Base.Libc.dup does) is not supported for sockets.
    const _WSA_FLAG_OVERLAPPED = UInt32(0x01)
    const _FROM_PROTOCOL_INFO = Cint(-1)
    const _INVALID_SOCKET = ~UInt(0)

    function _dup_socketfd(fd::SocketFD)
        # WSAPROTOCOL_INFOW is 372 bytes, we over-allocate rather than
        # transcribe the layout since we only pass it back to winsock.
        info = zeros(UInt8, 512)
        pid = @ccall "kernel32".GetCurrentProcessId()::UInt32
        ret = @ccall "ws2_32".WSADuplicateSocketW(_handle_to_uint(fd)::UInt,
                                                  pid::UInt32,
                                                  info::Ptr{Cvoid})::Cint
        if ret != 0
            return nothing
        end

        dupfd = @ccall "ws2_32".WSASocketW(_FROM_PROTOCOL_INFO::Cint,
                                           _FROM_PROTOCOL_INFO::Cint,
                                           _FROM_PROTOCOL_INFO::Cint,
                                           info::Ptr{Cvoid},
                                           0::UInt32,
                                           _WSA_FLAG_OVERLAPPED::UInt32)::UInt
        if dupfd == _INVALID_SOCKET
            return nothing
        end

        return _socketfd(dupfd)
    end

    _close_socketfd(fd::SocketFD) =
        @ccall "ws2_32".closesocket(_handle_to_uint(fd)::UInt)::Cint

    _socket_error() = @ccall "ws2_32".WSAGetLastError()::Cint

    _handle_to_uint(fd::SocketFD) = UInt(Base.cconvert(Ptr{Cvoid}, fd))

    _socket_t_value(fd::SocketFD) = lib.socket_t(_handle_to_uint(fd))
    # A RawFD is a CRT fd, so it needs converting to a handle first.
    _socket_t_value(fd::RawFD) = _socket_t_value(Base.Libc._get_osfhandle(fd))
    _socket_t_value(fd::Integer) = lib.socket_t(fd)
else
    const SocketFD = RawFD

    _socketfd(fd::Integer) = RawFD(fd)

    # RawFD is a primitive type, Cint(::RawFD) doesn't exist.
    _socket_t_value(fd::RawFD) = Base.cconvert(lib.socket_t, fd)
    _socket_t_value(fd::Integer) = lib.socket_t(fd)

    function _dup_socketfd(fd::SocketFD)
        dupfd = Base.Libc.dup(fd)
        return dupfd == RawFD(-1) ? nothing : dupfd
    end

    _close_socketfd(fd::SocketFD) = @ccall close(fd::Cint)::Cint

    _socket_error() = Base.Libc.errno()
end

# libssh returns SSH_INVALID_SOCKET for a disconnected session. Note that this
# must be checked on the raw socket_t, before converting it with _socketfd().
_is_invalid_fd(fd::Integer) = fd == lib.SSH_INVALID_SOCKET

include("utils.jl")
include("gssapi.jl")
include("pki.jl")
include("callbacks.jl")
include("session.jl")
include("channel.jl")
include("message.jl")
include("server.jl")

import Base: Filesystem
include("sftp.jl")

@compile_workload begin
    port, server = Sockets.listenany(Sockets.localhost, 2222)
    port = Int(port)
    close(server)
    server = DemoServer(port; password="foo", auth_methods=[AuthMethod_Password])

    session = Session(Sockets.localhost, port)
    @assert isconnected(session)
    @assert userauth_password(session, "foo") == AuthStatus_Success
    close(session)

    close(server)
end

end
