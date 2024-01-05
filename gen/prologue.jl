using libssh_jll
using DocStringExtensions

struct LibSSHException <: Exception
    msg::String
end
