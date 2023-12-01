module Callbacks

import ..lib
import ..LibSSH as ssh

function _auth_password(ptr::lib.ssh_session, user_cstr::Cstring, password_cstr::Cstring, callbacks_ptr::Ptr{Cvoid})::Cint
    session = ssh.Session(ptr; own=false)
    user = unsafe_string(user_cstr)
    password = unsafe_string(password_cstr)
    callbacks = unsafe_pointer_to_objref(callbacks_ptr)

    ret::ssh.AuthStatus = ssh.AuthStatus_Error
    try
        ret = callbacks.functions[:auth_password](session, user, password, callbacks.userdata)
    catch ex
        @error "Exception in auth_password callback!" exception=ex
    end

    return Cint(ret)
end

function _auth_none(ptr::lib.ssh_session, user_cstr::Cstring, callbacks_ptr::Ptr{Cvoid})::Cint
    session = ssh.Session(ptr; own=false)
    user = unsafe_string(user_cstr)
    callbacks::ServerCallbacks = unsafe_pointer_to_objref(callbacks_ptr)

    ret::ssh.AuthStatus = ssh.AuthStatus_Error
    try
        ret = callbacks.functions[:auth_none](session, user, callbacks.userdata)
    catch ex
        @error "Exception in auth_none callback!" exception=ex
    end

    return Cint(ret)
end

function _channel_open(ptr::lib.ssh_session, callbacks_ptr::Ptr{Cvoid})::lib.ssh_channel
    session = ssh.Session(ptr; own=false)
    callbacks::ServerCallbacks = unsafe_pointer_to_objref(callbacks_ptr)

    result::Union{ssh.SshChannel, Nothing} = nothing
    try
        ret = callbacks.functions[:channel_open](session, callbacks.userdata)
    catch ex
        @error "Exception in channel_open callback!" exception=ex
    end

    return isnothing(result) ? lib.ssh_channel() : result.ptr
end

mutable struct ServerCallbacks
    cb_struct::Union{lib.ssh_server_callbacks_struct, Nothing}
    userdata::Any
    functions::Dict{Symbol, Function}

    function ServerCallbacks(userdata=nothing;
                             auth_password_function=nothing, auth_none_function=nothing,
                             # auth_gssapi_mic_function=nothing, auth_pubkey_function=nothing,
                             # service_request_function=nothing,
                             channel_open_request_session_function=nothing,
                             # gssapi_select_oid_function=nothing, gssapi_accept_sec_ctx_function=nothing,
                             # gssapi_verify_mic_function=nothing
                             )
        self = new(nothing, userdata, Dict())

        auth_password_cfunc = if !isnothing(auth_password_function)
            self.functions[:auth_password] = auth_password_function
            @cfunction(_auth_password, Cint, (lib.ssh_session, Cstring, Cstring, Ptr{Cvoid}))
        else
            C_NULL
        end

        auth_none_cfunc = if !isnothing(auth_none_function)
            self.functions[:auth_none] = auth_none_function
            @cfunction(_auth_none, Cint, (lib.ssh_session, Cstring, Ptr{Cvoid}))
        else
            C_NULL
        end

        open_request_cfunc = if !isnothing(channel_open_request_session_function)
            self.functions[:channel_open] = channel_open_request_session_function
            @cfunction(_channel_open, lib.ssh_channel, (lib.ssh_session, Ptr{Cvoid}))
        else
            C_NULL
        end

        self.cb_struct = lib.ssh_server_callbacks_struct(sizeof(lib.ssh_server_callbacks_struct), # size (usually done with ssh_callback_int())
                                                         pointer_from_objref(self), # userdata points to self
                                                         auth_password_cfunc, auth_none_cfunc,
                                                         C_NULL, C_NULL,
                                                         C_NULL, open_request_cfunc,
                                                         C_NULL, C_NULL,
                                                         C_NULL)

        return self
    end
end

end
