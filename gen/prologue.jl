using libssh_jll
using DocStringExtensions

"""
$(TYPEDEF)

A custom exception type to represent errors from libssh's C API.
"""
struct LibSSHException <: Exception
    msg::String
end
