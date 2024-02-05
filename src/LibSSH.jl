module LibSSH

export SSH_LOG_NOLOG, SSH_LOG_WARNING, SSH_LOG_PROTOCOL, SSH_LOG_PACKET, SSH_LOG_FUNCTIONS

import Sockets
import FileWatching

using DocStringExtensions

include("bindings.jl")
using .lib
import .lib: LibSSHException, ssh_options_get, ssh_options_set, SSH_OK, SSH_ERROR, SSH_AGAIN, SSH_EOF


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

"""
$(TYPEDSIGNATURES)

Check if GSSAPI support is available (currently only Linux and FreeBSD).
"""
function gssapi_available()
    Sys.islinux() || Sys.isfreebsd()
end

# Safe wrapper around poll_fd(). There's a race condition in older Julia
# versions between the loop condition evaluation and this line, so we wrap
# poll_fd() in a try-catch in case the bind (and thus the file descriptor) has
# been closed in the meantime, which would cause poll_fd() to throw an IOError:
# https://github.com/JuliaLang/julia/pull/52377
function _safe_poll_fd(args...; kwargs...)
    result = nothing
    try
        result = FileWatching.poll_fd(args...; kwargs...)
    catch ex
        if !(ex isa Base.IOError)
            rethrow()
        end
    end

    return result
end

include("pki.jl")
include("callbacks.jl")
include("session.jl")
include("channel.jl")
include("message.jl")
include("server.jl")

end
