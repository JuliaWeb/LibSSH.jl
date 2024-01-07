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

@enum AuthStatus begin
    AuthStatus_Error = Int(SSH_AUTH_ERROR)
    AuthStatus_Denied = Int(SSH_AUTH_DENIED)
    AuthStatus_Partial = Int(SSH_AUTH_PARTIAL)
    AuthStatus_Success = Int(SSH_AUTH_SUCCESS)
    AuthStatus_Info = Int(SSH_AUTH_INFO)
    AuthStatus_Again = Int(SSH_AUTH_AGAIN)
end

@enum RequestType begin
    RequestType_Auth = Int(lib.SSH_REQUEST_AUTH)
    RequestType_ChannelOpen = Int(lib.SSH_REQUEST_CHANNEL_OPEN)
    RequestType_Channel = Int(lib.SSH_REQUEST_CHANNEL)
    RequestType_Service = Int(lib.SSH_REQUEST_SERVICE)
    RequestType_Global = Int(lib.SSH_REQUEST_GLOBAL)
end

include("pki.jl")
include("session.jl")
include("callbacks.jl")
include("channel.jl")
include("message.jl")
include("server.jl")

end
