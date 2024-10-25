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
    All of these are also properties that can be set after creation.

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

        self.cb_struct = lib.ssh_server_callbacks_struct(sizeof(lib.ssh_server_callbacks_struct), # size (usually done with ssh_callback_init())
                                                         pointer_from_objref(self), # userdata points to self
                                                         C_NULL, C_NULL,
                                                         C_NULL, C_NULL,
                                                         C_NULL, C_NULL,
                                                         C_NULL, C_NULL,
                                                         C_NULL)
        self.on_auth_password = on_auth_password
        self.on_auth_none = on_auth_none
        self.on_auth_gssapi_mic = on_auth_gssapi_mic
        self.on_auth_pubkey = on_auth_pubkey
        self.on_service_request = on_service_request
        self.on_channel_open_request_session = on_channel_open_request_session

        return self
    end
end

function Base.setproperty!(self::ServerCallbacks, name::Symbol, value)
    ptr = self.cb_struct

    if name === :on_auth_password
        ptr.auth_password_function = @_gencb(:auth_password, value,
                                             ssh.AuthStatus, ssh.AuthStatus_Error, Cint,
                                             Cint, (lib.ssh_session, Cstring, Cstring, Ptr{Cvoid}))
    elseif name === :on_auth_none
        ptr.auth_none_function = @_gencb(:auth_none, value,
                                         ssh.AuthStatus, ssh.AuthStatus_Error, Cint,
                                         Cint, (lib.ssh_session, Cstring, Ptr{Cvoid}))
    elseif name === :on_auth_gssapi_mic
        ptr.auth_gssapi_mic_function = @_gencb(:auth_gssapi, value,
                                               ssh.AuthStatus, ssh.AuthStatus_Error, Cint,
                                               Cint, (lib.ssh_session, Cstring, Cstring, Ptr{Cvoid}))
    elseif name === :on_auth_pubkey
        ptr.auth_pubkey_function = @_gencb(:auth_pubkey, value,
                                           ssh.AuthStatus, ssh.AuthStatus_Error, Cint,
                                           Cint, (lib.ssh_session, Cstring, lib.ssh_key, Cchar, Ptr{Cvoid}))
    elseif name === :on_service_request
        ptr.service_request_function = @_gencb(:service_request, value,
                                               Bool, false, ret -> ret ? 0 : -1,
                                               Cint, (lib.ssh_session, Cstring, Ptr{Cvoid}))
    elseif name === :on_channel_open_request_session
        ptr.channel_open_request_session_function = @_gencb(:channel_open, value,
                                                            Union{ssh.SshChannel, Nothing}, nothing, ret -> isnothing(ret) ? lib.ssh_channel() : ret.ptr,
                                                            lib.ssh_channel, (lib.ssh_session, Ptr{Cvoid}))
    else
        setfield!(self, name, value)
    end
end


## Channel callbacks bindings

"""
$(TYPEDEF)

Wrapper around `lib.ssh_channel_callbacks_struct`.
"""
mutable struct ChannelCallbacks
    userdata::Any
    functions::Dict{Symbol, Function}
    c_result_types::Dict{Symbol, DataType}
    c_arg_types::Dict{Symbol}
    jl_result_types::Dict{Symbol}
    jl_result_defaults::Dict{Symbol}
    jl_result_to_ctype::Dict{Symbol}
    cb_struct::lib.ssh_channel_callbacks_struct

    @doc """
    $(TYPEDSIGNATURES)

    Create a callbacks object to set on a channel. A default function is
    registered for each callback and it will print a warning if a callback was
    requested but not found, so you don't need to set all of the callbacks for
    the channel to work properly. The only exceptions are:
    - `on_write_wontblock=Returns(0)`
    - `on_open_response=Returns(nothing)`
    - `on_request_response=Returns(nothing)`

    Which have default callbacks because they're always called but rarely
    necessary to set explicitly.

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
    All of these are also properties that can be set after creation.

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
    - [`on_open_response`](@ref lib.ssh_channel_open_resp_callback): `f(::Session, ::SshChannel, ::Bool, userdata)::Nothing`
    - [`on_request_response`](@ref lib.ssh_channel_request_resp_callback): `f(::Session, ::SshChannel, userdata)::Nothing`
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
                              on_write_wontblock::Union{Function, Nothing}=Returns(0),
                              on_open_response::Union{Function, Nothing}=Returns(nothing),
                              on_request_response::Union{Function, Nothing}=Returns(nothing))
        self = new(userdata,
                   Dict{Symbol, Function}(),
                   Dict{Symbol, DataType}(),
                   Dict{Symbol, Any}(),
                   Dict{Symbol, Any}(),
                   Dict{Symbol, Any}(),
                   Dict{Symbol, Any}())

        cb_struct = lib.ssh_channel_callbacks_struct(sizeof(lib.ssh_channel_callbacks_struct), # size (see: ssh_callback_init())
                                                     pointer_from_objref(self), # userdata points to self
                                                     C_NULL, C_NULL,
                                                     C_NULL, C_NULL,
                                                     C_NULL, C_NULL,
                                                     C_NULL, C_NULL,
                                                     C_NULL, C_NULL,
                                                     C_NULL, C_NULL,
                                                     C_NULL, C_NULL,
                                                     C_NULL,
                                                     C_NULL,
                                                     C_NULL)
        # Call setfield!() explicitly to fully initialize the object so that all
        # other calls to setproperty!() will work.
        setfield!(self, :cb_struct, cb_struct)

        self.on_data = on_data
        self.on_eof = on_eof
        self.on_close = on_close
        self.on_signal = on_signal
        self.on_exit_status = on_exit_status
        self.on_exit_signal = on_exit_signal
        self.on_pty_request = on_pty_request
        self.on_shell_request = on_shell_request
        self.on_auth_agent_req = on_auth_agent_req
        self.on_x11_req = on_x11_req
        self.on_pty_window_change = on_pty_window_change
        self.on_exec_request = on_exec_request
        self.on_env_request = on_env_request
        self.on_subsystem_request = on_subsystem_request
        self.on_write_wontblock = on_write_wontblock
        self.on_open_response = on_open_response
        self.on_request_response = on_request_response

        return self
    end
end

function Base.setproperty!(self::ChannelCallbacks, name::Symbol, value)
    ptr = self.cb_struct

    # Why do some of these callbacks use 1 for denied and some -1? Who knows ¯\_(ツ)_/¯
    if name === :on_data
        ptr.channel_data_function              = @_gencb(:channel_data, value,
                                                         Int, 0, Cint,
                                                         Cint, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}, Cuint, Cint, Ptr{Cvoid}))
    elseif name === :on_eof
        ptr.channel_eof_function               = @_gencb(:channel_eof, value,
                                                         Nothing, nothing, identity,
                                                         Cvoid, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}))
    elseif name === :on_close
        ptr.channel_close_function             = @_gencb(:channel_close, value,
                                                         Nothing, nothing, identity,
                                                         Cvoid, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}))
    elseif name === :on_signal
        ptr.channel_signal_function            = @_gencb(:channel_signal, value,
                                                         Nothing, nothing, identity,
                                                         Cvoid, (lib.ssh_session, lib.ssh_channel, Cstring, Ptr{Cvoid}))

    elseif name === :on_exit_status
        ptr.channel_exit_status_function       = @_gencb(:channel_exit_status, value,
                                                         Nothing, nothing, identity,
                                                         Cvoid, (lib.ssh_session, lib.ssh_channel, Cint, Ptr{Cvoid}))
    elseif name === :on_exit_signal
        ptr.channel_exit_signal_function       = @_gencb(:channel_exit_signal, value,
                                                         Nothing, nothing, identity,
                                                         Cvoid, (lib.ssh_session, lib.ssh_channel, Cstring, Cint, Cstring, Cstring, Ptr{Cvoid}))

    elseif name === :on_pty_request
        ptr.channel_pty_request_function       = @_gencb(:channel_pty_request, value,
                                                         Bool, false, ret -> Cint(ret ? 0 : -1),
                                                         Cint, (lib.ssh_session, lib.ssh_channel, Cstring, Cint, Cint, Cint, Cint, Ptr{Cvoid}))
    elseif name === :on_shell_request
        ptr.channel_shell_request_function     = @_gencb(:channel_shell_request, value,
                                                         Bool, false, ret -> Cint(ret ? 0 : 1),
                                                         Cint, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}))
    elseif name === :on_auth_agent_req
        ptr.channel_auth_agent_req_function    = @_gencb(:channel_auth_agent_req, value,
                                                         Nothing, nothing, identity,
                                                         Cvoid, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}))
    elseif name === :on_x11_req
        ptr.channel_x11_req_function           = @_gencb(:channel_x11_req, value,
                                                         Nothing, nothing, identity,
                                                         Cvoid, (lib.ssh_session, lib.ssh_channel, Cint, Cstring, Cstring, Cuint, Ptr{Cvoid}))
    elseif name === :on_pty_window_change
        ptr.channel_pty_window_change_function = @_gencb(:channel_pty_window_change, value,
                                                         Bool, false, ret -> Cint(ret ? 0 : -1),
                                                         Cint, (lib.ssh_session, lib.ssh_channel, Cint, Cint, Cint, Cint, Ptr{Cvoid}))

    elseif name === :on_exec_request
        ptr.channel_exec_request_function      = @_gencb(:channel_exec_request, value,
                                                         Bool, false, ret -> Cint(ret ? 0 : 1),
                                                         Cint, (lib.ssh_session, lib.ssh_channel, Cstring, Ptr{Cvoid}))
    elseif name === :on_env_request
        ptr.channel_env_request_function       = @_gencb(:channel_env_request, value,
                                                         Bool, false, ret -> Cint(ret ? 0 : 1),
                                                         Cint, (lib.ssh_session, lib.ssh_channel, Cstring, Cstring, Ptr{Cvoid}))

    elseif name === :on_subsystem_request
        ptr.channel_subsystem_request_function = @_gencb(:channel_subsystem_request, value,
                                                         Bool, false, ret -> Cint(ret ? 0 : 1),
                                                         Cint, (lib.ssh_session, lib.ssh_channel, Cstring, Ptr{Cvoid}))
    elseif name === :on_write_wontblock
        ptr.channel_write_wontblock_function   = @_gencb(:channel_write_wontblock, value,
                                                         Int, 0, Cint,
                                                         Cint, (lib.ssh_session, lib.ssh_channel, Cuint, Ptr{Cvoid}))
    elseif name === :on_open_response
        ptr.channel_open_response_function     = @_gencb(:channel_open_response, value,
                                                         Nothing, nothing, identity,
                                                         Cvoid, (lib.ssh_session, lib.ssh_channel, Bool, Ptr{Cvoid}))
    elseif name === :on_request_response
        ptr.channel_request_response_function  = @_gencb(:channel_request_response, value,
                                                         Nothing, nothing, identity,
                                                         Cvoid, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}))
    else
        setfield!(self, name, value)
    end
end

end
