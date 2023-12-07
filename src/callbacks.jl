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
    converted_args = map(_c_to_jl, args[1:end - 1])

    # Call user handler
    try
        jl_result = callbacks.functions[key](converted_args..., callbacks.userdata)
    catch ex
        @error "Exception in $(key) callback!" exception=(ex, catch_backtrace())
    end

    # Attempt to convert the result to a C-compatible type
    try
        c_result = jl2c(jl_result)
    catch ex
        @error "Exception while converting $(jl_type) to $(c_type)!" exception=(ex, catch_backtrace())
    end

    return c_result
end

"""
Helper macro to either generate a cfunction for a callback, or return C_NULL if
the user didn't pass a callback. Strictly only for internal use.
"""
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

mutable struct ServerCallbacks
    cb_struct::Union{lib.ssh_server_callbacks_struct, Nothing}
    userdata::Any
    functions::Dict{Symbol, Function}
    c_result_types::Dict{Symbol, DataType}
    c_arg_types::Dict{Symbol}
    jl_result_types::Dict{Symbol}
    jl_result_defaults::Dict{Symbol}
    jl_result_to_ctype::Dict{Symbol}

    function ServerCallbacks(userdata=nothing;
                             auth_password_function=nothing, auth_none_function=nothing,
                             auth_gssapi_mic_function=nothing, auth_pubkey_function=nothing,
                             service_request_function=nothing, channel_open_request_session_function=nothing,

                             # These GSSAPI functions are disabled because they're currently undocumented
                             # gssapi_select_oid_function=nothing, gssapi_accept_sec_ctx_function=nothing,
                             # gssapi_verify_mic_function=nothing
                             )
        self = new(nothing, userdata,
                   Dict{Symbol, Function}(),
                   Dict{Symbol, DataType}(),
                   Dict{Symbol, Any}(),
                   Dict{Symbol, Any}(),
                   Dict{Symbol, Any}(),
                   Dict{Symbol, Any}())

        auth_password_cfunc = @_gencb(:auth_password, auth_password_function,
                                      ssh.AuthStatus, ssh.AuthStatus_Error, Cint,
                                      Cint, (lib.ssh_session, Cstring, Cstring, Ptr{Cvoid}))
        auth_none_cfunc = @_gencb(:auth_none, auth_none_function,
                                  ssh.AuthStatus, ssh.AuthStatus_Error, Cint,
                                  Cint, (lib.ssh_session, Cstring, Ptr{Cvoid}))
        auth_gssapi_cfunc = @_gencb(:auth_gssapi, auth_gssapi_mic_function,
                                    ssh.AuthStatus, ssh.AuthStatus_Error, Cint,
                                    Cint, (lib.ssh_session, Cstring, Cstring, Ptr{Cvoid}))
        auth_pubkey_cfunc = @_gencb(:auth_pubkey, auth_pubkey_function,
                                    ssh.AuthStatus, ssh.AuthStatus_Error, Cint,
                                    Cint, (lib.ssh_session, Cstring, Ptr{lib.ssh_key_struct}, Cchar, Ptr{Cvoid}))

        service_request_cfunc = @_gencb(:service_request, service_request_function,
                                        Bool, false, ret -> ret ? 0 : -1,
                                        Cint, (lib.ssh_session, Cstring, Ptr{Cvoid}))
        open_request_cfunc = @_gencb(:channel_open, channel_open_request_session_function,
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

mutable struct ChannelCallbacks
    cb_struct::Union{lib.ssh_channel_callbacks_struct, Nothing}
    userdata::Any
    functions::Dict{Symbol, Function}
    c_result_types::Dict{Symbol, DataType}
    c_arg_types::Dict{Symbol}
    jl_result_types::Dict{Symbol}
    jl_result_defaults::Dict{Symbol}
    jl_result_to_ctype::Dict{Symbol}

    function ChannelCallbacks(userdata=nothing;
                              channel_data_function=nothing, channel_eof_function=nothing,
                              channel_close_function=nothing, channel_signal_function=nothing,
                              channel_exit_status_function=nothing, channel_exit_signal_function=nothing,
                              channel_pty_request_function=nothing, channel_shell_request_function=nothing,
                              channel_auth_agent_req_function=nothing, channel_x11_req_function=nothing,
                              channel_pty_window_change_function=nothing, channel_exec_request_function=nothing,
                              channel_env_request_function=nothing, channel_subsystem_request_function=nothing,
                              channel_write_wontblock_function=nothing)
        self = new(nothing, userdata,
                   Dict{Symbol, Function}(),
                   Dict{Symbol, DataType}(),
                   Dict{Symbol, Any}(),
                   Dict{Symbol, Any}(),
                   Dict{Symbol, Any}(),
                   Dict{Symbol, Any}())

        # Why do some of these callbacks use 1 for denied and some -1? Who knows ¯\_(ツ)_/¯
        data_cfunc              = @_gencb(:channel_data, channel_data_function,
                                          Int, 0, Cint,
                                          Cint, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}, Cuint, Cint, Ptr{Cvoid}))
        eof_cfunc               = @_gencb(:channel_eof, channel_eof_function,
                                          Nothing, nothing, identity,
                                          Cvoid, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}))
        close_cfunc             = @_gencb(:channel_close, channel_close_function,
                                          Nothing, nothing, identity,
                                          Cvoid, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}))
        signal_cfunc            = @_gencb(:channel_signal, channel_signal_function,
                                          Nothing, nothing, identity,
                                          Cvoid, (lib.ssh_session, lib.ssh_channel, Cstring, Ptr{Cvoid}))

        exit_status_cfunc       = @_gencb(:channel_exit_status, channel_exit_status_function,
                                          Nothing, nothing, identity,
                                          Cvoid, (lib.ssh_session, lib.ssh_channel, Cint, Ptr{Cvoid}))
        exit_signal_cfunc       = @_gencb(:channel_exit_signal, channel_exit_signal_function,
                                          Nothing, nothing, identity,
                                          Cvoid, (lib.ssh_session, lib.ssh_channel, Cstring, Cint, Cstring, Cstring, Ptr{Cvoid}))

        pty_request_cfunc       = @_gencb(:channel_pty_request, channel_pty_request_function,
                                          Bool, false, ret -> Cint(ret ? 0 : -1),
                                          Cint, (lib.ssh_session, lib.ssh_channel, Cstring, Cint, Cint, Cint, Cint, Ptr{Cvoid}))
        shell_request_cfunc     = @_gencb(:channel_shell_request, channel_shell_request_function,
                                          Bool, false, ret -> Cint(ret ? 0 : 1),
                                          Cint, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}))
        auth_agent_req_cfunc    = @_gencb(:channel_auth_agent_req, channel_auth_agent_req_function,
                                          Nothing, nothing, identity,
                                          Cvoid, (lib.ssh_session, lib.ssh_channel, Ptr{Cvoid}))
        x11_req_cfunc           = @_gencb(:channel_x11_req, channel_x11_req_function,
                                          Nothing, nothing, identity,
                                          Cvoid, (lib.ssh_session, lib.ssh_channel, Cint, Cstring, Cstring, Cuint, Ptr{Cvoid}))
        pty_window_change_cfunc = @_gencb(:channel_pty_window_change, channel_pty_window_change_function,
                                          Bool, false, ret -> Cint(ret ? 0 : -1),
                                          Cint, (lib.ssh_session, lib.ssh_channel, Cint, Cint, Cint, Cint, Ptr{Cvoid}))

        exec_request_cfunc      = @_gencb(:channel_exec_request, channel_exec_request_function,
                                          Bool, false, ret -> Cint(ret ? 0 : 1),
                                          Cint, (lib.ssh_session, lib.ssh_channel, Cstring, Ptr{Cvoid}))
        env_request_cfunc       = @_gencb(:channel_env_request, channel_env_request_function,
                                          Bool, false, ret -> Cint(ret ? 0 : 1),
                                          Cint, (lib.ssh_session, lib.ssh_channel, Cstring, Cstring, Ptr{Cvoid}))

        subsystem_request_cfunc = @_gencb(:channel_subsystem_request, channel_subsystem_request_function,
                                          Bool, false, ret -> Cint(ret ? 0 : 1),
                                          Cint, (lib.ssh_session, lib.ssh_channel, Cstring, Ptr{Cvoid}))
        write_wontblock_cfunc   = @_gencb(:channel_write_wontblock, channel_write_wontblock_function,
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

"""
$(TYPEDSIGNATURES)

Wrapper around `LibSSH.lib.ssh_set_channel_callbacks()`. Will throw a
`LibSSHException` if setting the callbacks failed.
"""
function set_channel_callbacks(sshchan::ssh.SshChannel, callbacks::ChannelCallbacks)
    ret = lib.ssh_set_channel_callbacks(sshchan.ptr, Ref(callbacks.cb_struct))
    if ret != ssh.SSH_OK
        throw(LibSSHException("Error when setting channel callbacks: $(ret)"))
    end
end

end
