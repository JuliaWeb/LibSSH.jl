module LibSSH

export SSH_LOG_NOLOG, SSH_LOG_WARNING, SSH_LOG_PROTOCOL, SSH_LOG_PACKET, SSH_LOG_FUNCTIONS

import FileWatching

using DocStringExtensions

include("libssh.jl")
using .lib
import .lib: ssh_options_get, ssh_options_set, SSH_OK, SSH_ERROR, SSH_AGAIN


struct LibSSHException <: Exception
    msg::String
end

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
    AuthStatus_Again = Int(SSH_AUTH_AGAIN)
end

include("session.jl")
include("channel.jl")
include("callbacks.jl")
include("server.jl")

end
