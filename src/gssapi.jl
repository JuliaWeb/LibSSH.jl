module Gssapi

using DocStringExtensions
import Kerberos_krb5_jll: libgssapi_krb5

import ..LibSSH as ssh


const krb5_context = Ptr{Cvoid}
const krb5_ccache = Ptr{Cvoid}
const krb5_principal = Ptr{Cvoid}

"""
$(TYPEDSIGNATURES)

Check if GSSAPI support is available. Currently this is only available on Linux
and FreeBSD because it's difficult to cross-compile `Kerberos_krb5_jll` for
other platforms (which is what we depend on for GSSAPI).
"""
function isavailable()
    Sys.islinux() || Sys.isfreebsd()
end

mutable struct Krb5Context
    ptr::Union{krb5_context, Nothing}

    function Krb5Context()
        context_ref = Ref{krb5_context}()
        ret = @ccall libgssapi_krb5.krb5_init_context(context_ref::Ptr{krb5_context})::Cint
        if ret != 0
            error("Error initializing Kerberos context: $(ret)")
        end

        self = new(context_ref[])
        finalizer(self) do context
            @ccall libgssapi_krb5.krb5_free_context(context.ptr::krb5_context)::Cvoid
            context.ptr = nothing
        end
    end
end

mutable struct Krb5Ccache
    ptr::Union{krb5_ccache, Nothing}
    context::Krb5Context

    function Krb5Ccache(context::Krb5Context)
        cache_ref = Ref{krb5_ccache}()
        ret = @ccall libgssapi_krb5.krb5_cc_default(context.ptr::krb5_context,
                                                    cache_ref::Ptr{krb5_ccache})::Cint
        if ret != 0
            error("Error initializing default Kerberos cache: $(ret)")
        end

        self = new(cache_ref[], context)
        finalizer(self) do cache
            @ccall libgssapi_krb5.krb5_cc_close(cache.context.ptr::krb5_context,
                                                cache.ptr::krb5_ccache)::Cint
            cache.ptr = nothing
        end
    end
end

mutable struct Krb5Principle
    ptr::Union{krb5_principal, Nothing}
    context::Krb5Context

    function Krb5Principle(context::Krb5Context, cache::Krb5Ccache)
        principal_ref = Ref{krb5_principal}()
        ret = @ccall libgssapi_krb5.krb5_cc_get_principal(context.ptr::krb5_context,
                                                          cache.ptr::krb5_ccache,
                                                          principal_ref::Ptr{krb5_principal})::Cint
        if ret != 0
            error("Error retrieving default principal: $(ret)")
        end

        self = new(principal_ref[], context)
        finalizer(self) do principal
            @ccall libgssapi_krb5.krb5_free_principal(principal.context.ptr::krb5_context,
                                                      principal.ptr::krb5_principal)::Cvoid
            principal.ptr = nothing
        end
    end
end

function krb5_unparse_name(context::Krb5Context, principal::Krb5Principle)
    name_ref = Ref{Cstring}()
    ret = @ccall libgssapi_krb5.krb5_unparse_name(context.ptr::krb5_context,
                                                  principal.ptr::krb5_principal,
                                                  name_ref::Ptr{Cstring})::Cint
    if ret != 0
        error("Error getting principal name: $(ret)")
    end

    name = unsafe_string(name_ref[])
    @ccall libgssapi_krb5.krb5_free_unparsed_name(context.ptr::krb5_context,
                                                  name_ref[]::Cstring)::Cvoid

    return name
end

"""
$(TYPEDSIGNATURES)

Returns the name of the default principal from the default credential cache, or
`nothing` if a principal with a valid ticket was not found. This can be used to
check if [`ssh.userauth_gssapi()`](@ref) can be called. Under the hood it uses:
- [`krb5_cc_default()`](https://web.mit.edu/kerberos/krb5-1.18/doc/appdev/refs/api/krb5_cc_default.html)
- [`krb5_cc_get_principal()`](https://web.mit.edu/kerberos/krb5-1.18/doc/appdev/refs/api/krb5_cc_get_principal.html)

# Throws
- `ErrorException`: If GSSAPI support is not available on the current platform
  (see [`isavailable()`](@ref)).
"""
function principal_name()
    if !isavailable()
        error("GSSAPI support not available, cannot get the principal name")
    end

    context = Krb5Context()
    cache = Krb5Ccache(context)

    # This will throw if a principal with a valid ticket doesn't exist
    principal = nothing
    try
        principal = Krb5Principle(context, cache)
    catch
        return nothing
    end

    return krb5_unparse_name(context, principal)
end

end
