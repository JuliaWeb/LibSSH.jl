module Callbacks

using DocStringExtensions

import ..lib
import ..LibSSH as ssh


function _c_to_jl(cvalue)
    if cvalue isa Cstring
        unsafe_string(cvalue)
    elseif cvalue isa Cint
        Int(cvalue)
    elseif cvalue isa Cuint
        UInt(cvalue)
    elseif cvalue isa Cchar
        Char(cvalue)
    elseif cvalue isa lib.ssh_session
        ssh.Session(cvalue; own=false)
    elseif cvalue isa lib.ssh_channel
        ssh.SshChannel(cvalue; own=false)
    elseif cvalue isa lib.ssh_key
        ssh.PKI.SshKey(cvalue; own=false)
    else
        cvalue
    end
end

function _callback_wrapper(key::Symbol, args...)
    # The last argument is always the userdata
    callbacks::Union{ServerCallbacks, ChannelCallbacks} = unsafe_pointer_to_objref((args[end])::Ptr{Cvoid})

    # Initialize the return value
    jl_type = callbacks.jl_result_types[key]
    c_type = callbacks.c_result_types[key]
    jl2c = callbacks.jl_result_to_ctype[key]
    jl_result::jl_type = callbacks.jl_result_defaults[key]
    c_result::c_type = jl2c(jl_result)

    # Throw an error if the user didn't set a callback
    if !haskey(callbacks.functions, key)
        @error "Callback $(key) was requested, but not provided!"
        return c_result
    end

    # Convert the arguments (apart from the userdata)
    converted_args = [_c_to_jl(arg) for arg in args[1:end - 1]]

    # Replace the two data arguments for the channel_data callback with a single array
    if key == :channel_data
        data_ptr::Ptr{Cvoid} = converted_args[3]
        data_len::UInt = converted_args[4]
        data = unsafe_wrap(Array, Ptr{UInt8}(data_ptr), data_len)
        converted_args[3] = data
        popat!(converted_args, 4)
    end

    # Call user handler
    try
        result = callbacks.functions[key](converted_args..., callbacks.userdata)

        # Only bother assigning the result if the return type is non-Nothing
        if jl_type != Nothing
            jl_result = result
        end
    catch ex
        @error "Exception in $(key) callback!" exception=(ex, catch_backtrace())
    end

    # Unset the pointers in any non-owning wrappers to ensure that they aren't
    # used outside of the callback.
    for arg in converted_args
        if arg isa ssh.Session || arg isa ssh.SshChannel || arg isa ssh.PKI.SshKey
            arg.ptr = nothing
        end
    end

    # Attempt to convert the result to a C-compatible type
    try
        c_result = jl2c(jl_result)
    catch ex
        @error "Exception while converting $(jl_type) to $(c_type)!" exception=(ex, catch_backtrace())
    end

    return c_result
end

#=
Helper macro to either generate a cfunction for a callback. Strictly only
for internal use. It must be called in a constructor with a `self` object
referencing the callback struct.

Depends on these fields being present in the containing struct:
- functions
- c_result_types
- c_arg_types
- jl_result_types
- jl_result_defaults
- jl_result_to_ctype
=#
function _gencb(key, user_callback,
                jl_return_type, jl_default, jl_result_to_ctype,
                c_return_type, c_arg_types)
    expr = quote
        let
            self.c_result_types[$key] = $c_return_type
            self.c_arg_types[$key] = $c_arg_types
            self.jl_result_types[$key] = $jl_return_type
            self.jl_result_defaults[$key] = $jl_default
            self.jl_result_to_ctype[$key] = $jl_result_to_ctype

            if !isnothing($user_callback)
                self.functions[$key] = $user_callback
            end

            @cfunction((args...) -> _callback_wrapper($key, args...), $c_return_type, $c_arg_types)
        end
    end

    return esc(expr)
end

macro _gencb(args...)
    _gencb(args...)
end

"""
$(TYPEDEF)

Wrapper around [`lib.ssh_server_callbacks_struct`](@ref).
"""
mutable struct ServerCallbacks
    cb_struct::Union{lib.ssh_server_callbacks_struct, Nothing}
    userdata::Any
    functions::Dict{Symbol, Function}
    c_result_types::Dict{Symbol, DataType}
    c_arg_types::Dict{Symbol}
    jl_result_types::Dict{Symbol}
    jl_result_defaults::Dict{Symbol}
    jl_result_to_ctype::Dict{Symbol}

    @doc """
    $(TYPEDSIGNATURES)

    Create a callbacks object to set on a server. This has basically the same
    behaviour as [`ChannelCallbacks()`](@ref), except that there are some
    callbacks that are unsupported due to lack of documentation:
    - `gssapi_select_oid_function`
    - `gssapi_accept_sec_ctx_function`
    - `gssapi_verify_mic_function`

    And `lib.ssh_key` arguments will be converted to a non-owning
    [`ssh.PKI.SshKey`](@ref).

    !!! warning
        Do not use [`ssh.Session`](@ref) or [`ssh.PKI.SshKey`](@ref) arguments
        outside the callback functions. They are temporary non-owning wrappers,
        and they will be unusable after the callback has been executed.

    # Arguments
    - `userdata`: An arbitrary object that will be passed to each callback.
    - [`on_auth_password`](@ref lib.ssh_auth_password_callback): `f(::Session, ::String, ::String, userdata)::AuthStatus`
    - [`on_auth_none`](@ref lib.ssh_auth_none_callback): `f(::Session, ::String, userdata)::AuthStatus`
    - [`on_auth_gssapi_mic`](@ref lib.ssh_auth_gssapi_mic_callback): `f(::Session, ::String, ::String, userdata)::AuthStatus`
    - [`on_auth_pubkey`](@ref lib.ssh_auth_pubkey_callback): `f(::Session, ::String, ::SshKey, ::Char, userdata)::AuthStatus`
    - [`on_service_request`](@ref lib.ssh_service_request_callback): `f(::Session, ::String, userdata)::Bool`
    - [`on_channel_open_request_session`](@ref lib.ssh_channel_open_request_session_callback): `f(::Session, userdata)::Union{SshChannel, Nothing}`
    """
    function ServerCallbacks(userdata=nothing;
                             on_auth_password::Union{Function, Nothing}=nothing,
                             on_auth_none::Union{Function, Nothing}=nothing,
                             on_auth_gssapi_mic::Union{Function, Nothing}=nothing,
                             on_auth_pubkey::Union{Function, Nothing}=nothing,
                             on_service_request::Union{Function, Nothing}=nothing,
                             on_channel_open_request_session::Union{Function, Nothing}=nothing,

                             # These GSSAPI functions are disabled because they're currently undocumented
                             # on_gssapi_select_oid=nothing,
                             # on_gssapi_accept_sec_ctx=nothing,
                             # on_gssapi_verify_mic=nothing
                             )
        self = new(nothing, userdata,
                   Dict{Symbol, Function}(),
                   Dict{Symbol, DataType}(),
                   Dict{Symbol, Any}(),
                   Dict{Symbol, Any}(),
                   Dict{Symbol, Any}(),
                   Dict{Symbol, Any}())

        auth_password_cfunc = @_gencb(:auth_password, on_auth_password,
                                      ssh.AuthStatus, ssh.AuthStatus_Error, Cint,
                                      Cint, (lib.ssh_session, Cstring, Cstring, Ptr{Cvoid}))
        auth_none_cfunc = @_gencb(:auth_none, on_auth_none,
                                  ssh.AuthStatus, ssh.AuthStatus_Error, Cint,
                                  Cint, (lib.ssh_session, Cstring, Ptr{Cvoid}))
        auth_gssapi_cfunc = @_gencb(:auth_gssapi, on_auth_gssapi_mic,
                                    ssh.AuthStatus, ssh.AuthStatus_Error, Cint,
                                    Cint, (lib.ssh_session, Cstring, Cstring, Ptr{Cvoid}))
        auth_pubkey_cfunc = @_gencb(:auth_pubkey, on_auth_pubkey,
                                    ssh.AuthStatus, ssh.AuthStatus_Error, Cint,
                                    Cint, (lib.ssh_session, Cstring, lib.ssh_key, Cchar, Ptr{Cvoid}))

        service_request_cfunc = @_gencb(:service_request, on_service_request,
                                        Bool, false, ret -> ret ? 0 : -1,
                                        Cint, (lib.ssh_session, Cstring, Ptr{Cvoid}))
        open_request_cfunc = @_gencb(:channel_open, on_channel_open_request_session,
                                     Union{ssh.SshChannel, Nothing}, nothing, ret -> isnothing(ret) ? lib.ssh_channel() : ret.ptr,
                                     lib.ssh_channel, (lib.ssh_session, Ptr{Cvoid}))

        self.cb_struct = lib.ssh_server_callbacks_struct(sizeof(lib.ssh_server_callbacks_struct), # size (usually done with ssh_callback_init())
                                                         pointer_from_objref(self), # userdata points to self
                                                         auth_password_cfunc, auth_none_cfunc,
                                                         auth_gssapi_cfunc, auth_pubkey_cfunc,
                                                         service_request_cfunc, open_request_cfunc,
                                                         C_NULL, C_NULL,
                                                         C_NULL)

        return self
    end
end


## Channel callbacks bindings

"""
$(TYPEDEF)

Wrapper around `lib.ssh_channel_callbacks_struct`.
"""
mutable struct ChannelCallbacks
    cb_struct::Union{lib.ssh_channel_callbacks_struct, Nothing}
    userdata::Any
    functions::Dict{Symbol, Function}
    c_result_types::Dict{Symbol, DataType}
    c_arg_types::Dict{Symbol}
    jl_result_types::Dict{Symbol}
    jl_result_defaults::Dict{Symbol}
    jl_result_to_ctype::Dict{Symbol}

    @doc """
    $(TYPEDSIGNATURES)

    Create a callbacks object to set on a channel. A default function is
    registered for each callback and it will print a warning if a callback was
    requested but not found, so you don't need to set all of the callbacks for
    the channel to work properly. The only exception is
    `channel_write_wontblock_function`, which is set to `Returns(0)` by default
    since it's always used but rarely necessary.

    The callback functions should all match the signature `f(::Session,
    ::SshChannel, args..., userdata)`. Note that some argument types will
    automatically be converted from the C types:
    - `lib.ssh_session` -> a non-owning [`ssh.Session`](@ref)
    - `lib.ssh_channel` -> a non-owning [`ssh.SshChannel`](@ref)
    - `Cstring` -> `String`
    - `Cint`/`Cuint`/`Cchar` -> `Int`/`UInt`/`Char`

    The userdata pointer in the C callback signatures will automatically be
    converted to its original Julia type. Boolean argments are not yet converted
    from their `Cint` types to `Bool`.

    !!! warning
        Do not use [`ssh.Session`](@ref) or [`ssh.SshChannel`](@ref) arguments
        outside the callback functions. They are temporary non-owning wrappers,
        and they will be unusable after the callback has been executed.

    # Arguments
    - `userdata`: An arbitrary object that will be passed to each callback
       function.
    - [`on_data`](@ref lib.ssh_channel_data_callback): `f(::Session, ::SshChannel, ::Vector{UInt8}, Int, userdata)::Int`
    - [`on_eof`](@ref lib.ssh_channel_eof_callback): `f(::Session, ::SshChannel, userdata)::Nothing`
    - [`on_close`](@ref lib.ssh_channel_close_callback): `f(::Session, ::SshChannel, userdata)::Nothing`
    - [`on_signal`](@ref lib.ssh_channel_signal_callback): `f(::Session, ::SshChannel, ::String, userdata)::Nothing`
    - [`on_exit_status`](@ref lib.ssh_channel_exit_status_callback): `f(::Session, ::SshChannel, ::Int, userdata)::Nothing`
    - [`on_exit_signal`](@ref lib.ssh_channel_exit_signal_callback): `f(::Session, ::SshChannel, ::String, ::Int, ::String, ::String, userdata)::Nothing`
    - [`on_pty_request`](@ref lib.ssh_channel_pty_request_callback): `f(::Session, ::SshChannel, ::String, ::Int, ::Int, ::Int, ::Int, userdata)::Bool`
    - [`on_shell_request`](@ref lib.ssh_channel_shell_request_callback): `f(::Session, ::SshChannel, userdata)::Bool`
    - [`on_auth_agent_req`](@ref lib.ssh_channel_auth_agent_req_callback): `f(::Session, ::SshChannel, userdata)::Nothing`
    - [`on_x11_req`](@ref lib.ssh_channel_x11_req_callback): `f(::Session, ::SshChannel, ::Int, ::String, ::String, ::UInt, userdata)::Nothing`
    - [`on_pty_window_change`](@ref lib.ssh_channel_pty_window_change_callback): `f(::Session, ::SshChannel, ::Int, ::Int, ::Int, ::Int, userdata)::Bool`
    - [`on_exec_request`](@ref lib.ssh_channel_exec_request_callback): `f(::Session, ::SshChannel, ::String, userdata)::Bool`
    - [`on_env_request`](@ref lib.ssh_channel_env_request_callback): `f(::Session, ::SshChannel, ::String, ::String, userdata)::Bool`
    - [`on_subsystem_request`](@ref lib.ssh_channel_subsystem_request_callback): `f(::Session, ::SshChannel, ::String, userdata)::Bool`
    - [`on_write_wontblock`](@ref lib.ssh_channel_write_wontblock_callback): `f(::Session, ::SshChannel, ::UInt, userdata)::Int`
    """
    function ChannelCallbacks(userdata::Any=nothing;
                              on_data::Union{Function, Nothing}=nothing,
                              on_eof::Union{Function, Nothing}=nothing,
                              on_close::Union{Function, Nothing}=nothing,
                              on_signal::Union{Function, Nothing}=nothing,
                              on_exit_status::Union{Function, Nothing}=nothing,
                              on_exit_signal::Union{Function, Nothing}=nothing,
                              on_pty_request::Union{Function, Nothing}=nothing,
                              on_shell_request::Union{Function, Nothing}=nothing,
                              on_auth_agent_req::Union{Function, Nothing}=nothing,
                              on_x11_req::Union{Function, Nothing}=nothing,
                              on_pty_window_change::Union{Function, Nothing}=nothing,
                              on_exec_request::Union{Function, Nothing}=nothing,
                              on_env_request::Union{Function, Nothing}=nothing,
                              on_subsystem_request::Union{Function, Nothing}=nothing,
                              on_write_wontblock=Returns(0))
        self = new(nothing, userdata,
                   Dict{Symbol, Function}(),
                   Dict{Symbol, DataType}(),
                   Dict{Symbol, Any}(),
                   Dict{Symbol, Any}(),
                   Dict{Symbol, Any}(),
                   Dict{Symbol, Any}())

        # Why do some of these callbacks use 1 for denied and some -1? Who knows ¯\_(ツ)_/¯
        data_cfunc              = @_gencb(:channel_data, on_data,
                                          Int, 0, Cint,
                                          Cint, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}, Cuint, Cint, Ptr{Cvoid}))
        eof_cfunc               = @_gencb(:channel_eof, on_eof,
                                          Nothing, nothing, identity,
                                          Cvoid, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}))
        close_cfunc             = @_gencb(:channel_close, on_close,
                                          Nothing, nothing, identity,
                                          Cvoid, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}))
        signal_cfunc            = @_gencb(:channel_signal, on_signal,
                                          Nothing, nothing, identity,
                                          Cvoid, (lib.ssh_session, lib.ssh_channel, Cstring, Ptr{Cvoid}))

        exit_status_cfunc       = @_gencb(:channel_exit_status, on_exit_status,
                                          Nothing, nothing, identity,
                                          Cvoid, (lib.ssh_session, lib.ssh_channel, Cint, Ptr{Cvoid}))
        exit_signal_cfunc       = @_gencb(:channel_exit_signal, on_exit_signal,
                                          Nothing, nothing, identity,
                                          Cvoid, (lib.ssh_session, lib.ssh_channel, Cstring, Cint, Cstring, Cstring, Ptr{Cvoid}))

        pty_request_cfunc       = @_gencb(:channel_pty_request, on_pty_request,
                                          Bool, false, ret -> Cint(ret ? 0 : -1),
                                          Cint, (lib.ssh_session, lib.ssh_channel, Cstring, Cint, Cint, Cint, Cint, Ptr{Cvoid}))
        shell_request_cfunc     = @_gencb(:channel_shell_request, on_shell_request,
                                          Bool, false, ret -> Cint(ret ? 0 : 1),
                                          Cint, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}))
        auth_agent_req_cfunc    = @_gencb(:channel_auth_agent_req, on_auth_agent_req,
                                          Nothing, nothing, identity,
                                          Cvoid, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}))
        x11_req_cfunc           = @_gencb(:channel_x11_req, on_x11_req,
                                          Nothing, nothing, identity,
                                          Cvoid, (lib.ssh_session, lib.ssh_channel, Cint, Cstring, Cstring, Cuint, Ptr{Cvoid}))
        pty_window_change_cfunc = @_gencb(:channel_pty_window_change, on_pty_window_change,
                                          Bool, false, ret -> Cint(ret ? 0 : -1),
                                          Cint, (lib.ssh_session, lib.ssh_channel, Cint, Cint, Cint, Cint, Ptr{Cvoid}))

        exec_request_cfunc      = @_gencb(:channel_exec_request, on_exec_request,
                                          Bool, false, ret -> Cint(ret ? 0 : 1),
                                          Cint, (lib.ssh_session, lib.ssh_channel, Cstring, Ptr{Cvoid}))
        env_request_cfunc       = @_gencb(:channel_env_request, on_env_request,
                                          Bool, false, ret -> Cint(ret ? 0 : 1),
                                          Cint, (lib.ssh_session, lib.ssh_channel, Cstring, Cstring, Ptr{Cvoid}))

        subsystem_request_cfunc = @_gencb(:channel_subsystem_request, on_subsystem_request,
                                          Bool, false, ret -> Cint(ret ? 0 : 1),
                                          Cint, (lib.ssh_session, lib.ssh_channel, Cstring, Ptr{Cvoid}))
        write_wontblock_cfunc   = @_gencb(:channel_write_wontblock, on_write_wontblock,
                                          Int, 0, Cint,
                                          Cint, (lib.ssh_session, lib.ssh_channel, Cuint, Ptr{Cvoid}))

        self.cb_struct = lib.ssh_channel_callbacks_struct(sizeof(lib.ssh_channel_callbacks_struct), # size (see: ssh_callback_init())
                                                          pointer_from_objref(self), # userdata points to self
                                                          data_cfunc, eof_cfunc,
                                                          close_cfunc, signal_cfunc,
                                                          exit_status_cfunc, exit_signal_cfunc,
                                                          pty_request_cfunc, shell_request_cfunc,
                                                          auth_agent_req_cfunc, x11_req_cfunc,
                                                          pty_window_change_cfunc, exec_request_cfunc,
                                                          env_request_cfunc, subsystem_request_cfunc,
                                                          write_wontblock_cfunc)

        return self
    end
end

end
