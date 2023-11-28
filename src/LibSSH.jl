module LibSSH

export SSH_LOG_NOLOG, SSH_LOG_WARNING, SSH_LOG_PROTOCOL, SSH_LOG_PACKET, SSH_LOG_FUNCTIONS

include("libssh.jl")

using DocStringExtensions

using .lib
import .lib: AuthMethod, ssh_options_get, ssh_options_set


struct LibSSHException <: Exception
    msg::String
end

include("session.jl")

end
