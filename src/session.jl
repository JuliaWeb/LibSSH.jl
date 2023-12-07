"""
`Session(ptr::lib.ssh_session)`

Represents an SSH session. Note that some properties such as the host and port are
implemented in `getproperty()`/`setproperty!()` by using the internal values of
the `ssh_session`, i.e. they aren't simply fields of the struct.

This inner constructor is only useful if you already have a `ssh_session`
(i.e. in a server). Do not use it if you want a client, use the other
constructor.
"""
mutable struct Session
    ptr::Union{lib.ssh_session, Nothing}
    log_verbosity::Int

    function Session(ptr::lib.ssh_session; log_verbosity=SSH_LOG_WARNING, own=true)
        # Set to non-blocking mode
        lib.ssh_set_blocking(ptr, 0)

        session = new(ptr, -1)
        session.log_verbosity = log_verbosity

        if own
            finalizer(close, session)
        end

        return session
    end
end

"""
$(TYPEDSIGNATURES)

Constructor for creating a client session. Use this if you want to connect to a
server.
"""
function Session(host::String, port=22; log_verbosity=SSH_LOG_WARNING)
    session_ptr = lib.ssh_new()
    if session_ptr == C_NULL
        throw(LibSSHException("Could not initialize Session for host $(host)"))
    end

    session = Session(session_ptr; log_verbosity)
    session.host = host
    session.port = port

    # Explicitly initialize the user, otherwise an error will be thrown when
    # retrieving it. Passing null will set it to the current user (see docs).
    ret = ssh_options_set(session.ptr, SSH_OPTIONS_USER, C_NULL)
    if ret != 0
        throw(LibSSHException("Error when initializing user: $(ret)"))
    end

    return session
end

"""
$(TYPEDSIGNATURES)

Closes a session, which will be unusable afterwards. It's safe to call this
multiple times.
"""
function Base.close(session::Session)
    if isopen(session)
        disconnect(session)
        lib.ssh_free(session.ptr)
        session.ptr = nothing
    end
end

Base.isopen(session::Session) = !isnothing(session.ptr)

"""
$(TYPEDSIGNATURES)

Get the last error set by libssh.
"""
function get_error(session::Session)
    if isnothing(session.ptr)
        throw(ArgumentError("Session data has been free'd, cannot get its error"))
    end

    ret = lib.ssh_get_error(Ptr{Cvoid}(session.ptr))
    return unsafe_string(ret)
end

# Mapping from option name to the corresponding enum and C type
const SESSION_PROPERTY_OPTIONS = Dict(:host => (SSH_OPTIONS_HOST, Cstring),
                                      :port => (SSH_OPTIONS_PORT, Cuint),
                                      :user => (SSH_OPTIONS_USER, Cstring),
                                      :log_verbosity => (SSH_OPTIONS_LOG_VERBOSITY, Cuint))
# These properties cannot be retrieved from the libssh API (i.e. with
# ssh_options_get()), so we store them in the Session object instead.
const SAVED_PROPERTIES = (:log_verbosity,)

function Base.propertynames(::Session, private::Bool=false)
    (:host, :port, :user, :log_verbosity, (private ? (:ptr,) : ())...)
end

function Base.getproperty(session::Session, name::Symbol)
    if name ∉ propertynames(session, true)
        error("type Session has no field $(name)")
    end

    # If it's a property that we save, then we return the saved value
    if name == :ptr || name in SAVED_PROPERTIES
        return getfield(session, name)
    end

    # Otherwise, we retrieve it from the ssh_session object
    ret = 0
    value = nothing
    is_string = false

    if name == :port
        # The port is a special option with its own function
        port = Ref{Cuint}(0)
        ret = lib.ssh_options_get_port(session.ptr, port)
        value = UInt(port[])
    else
        # All properties supported by ssh_options_get() are strings, so we know
        # that this option must be a string.
        is_string = true
        option = SESSION_PROPERTY_OPTIONS[name][1]

        out = Ref{Ptr{Cchar}}()
        ret = ssh_options_get(session.ptr, option, out)
    end

    if ret != 0
        throw(LibSSHException("Error getting $(name) from session: $(ret)"))
    end

    if is_string
        value = unsafe_string(out[])
        lib.ssh_string_free_char(out[])
    end

    return value
end

function Base.setproperty!(session::Session, name::Symbol, value)
    if name ∉ propertynames(session, true)
        error("type Session has no field $(name)")
    end

    if name == :ptr
        return setfield!(session, name, value)
    end

    # There's some weirdness around saving strings, so we do some special-casing
    # here to handle them.
    option, ctype = SESSION_PROPERTY_OPTIONS[name]
    is_string = ctype == Cstring
    GC.@preserve value begin
        cvalue = is_string ? Base.unsafe_convert(ctype, value) : Base.cconvert(ctype, value)
        ret = ssh_options_set(session.ptr, option, is_string ? Ptr{Cvoid}(cvalue) : Ref(cvalue))
    end

    if ret != 0
        throw(LibSSHException("Error setting Session.$(name) to $(value): $(ret)"))
    end

    # Some properties cannot be retrieved from the libssh API, so we also save
    # them explicitly in the Session.
    if name in SAVED_PROPERTIES
        saved_type = fieldtype(Session, name)
        setfield!(session, name, saved_type(value))
    end

    return value
end

"""
$(TYPEDSIGNATURES)

Waits for a session in non-blocking mode. If the session is in blocking mode the
function will return immediately.
"""
function Base.wait(session::Session)
    if lib.ssh_is_blocking(session.ptr) == 1
        return
    end

    poll_flags = lib.ssh_get_poll_flags(session.ptr)
    readable = (poll_flags & lib.SSH_READ_PENDING) > 0
    writable = (poll_flags & lib.SSH_WRITE_PENDING) > 0

    fd = RawFD(lib.ssh_get_fd(session.ptr))
    FileWatching.poll_fd(fd; readable, writable)

    return nothing
end

"""
$(TYPEDSIGNATURES)

Wrapper around `LibSSH.lib.ssh_connect()`.
"""
function connect(session::Session)
    while true
        ret = lib.ssh_connect(session.ptr)

        if ret == SSH_AGAIN
            wait(session)
        elseif ret == SSH_OK
            break
        else
            throw(LibSSHException("Error connecting to $(session.host) (port $(session.port)): $(get_error(session))"))
        end
    end
end

"""
$(TYPEDSIGNATURES)

Wrapper around `LibSSH.lib.ssh_disconnect()`.
"""
function disconnect(session::Session)
    if isconnected(session)
        lib.ssh_disconnect(session.ptr)
    end
end

"""
$(TYPEDSIGNATURES)

Wrapper around `LibSSH.lib.ssh_is_connected()`.
"""
function isconnected(session::Session)
    isnothing(session.ptr) ? false : lib.ssh_is_connected(session.ptr) == 1
end

"""
$(TYPEDSIGNATURES)

Wrapper around `LibSSH.lib.ssh_userauth_none()`. It will throw a
`LibSSHException` if an error occurs.
"""
function userauth_none(session::Session)
    while true
        ret = AuthStatus(lib.ssh_userauth_none(session.ptr, C_NULL))

        if ret == AuthStatus_Again
            wait(session)
        elseif ret == AuthStatus_Error
            throw(LibSSHException("Got AuthStatus_Error (SSH_AUTH_ERROR) when calling userauth_none()"))
        else
            return ret
        end
    end
end

"""
$(TYPEDSIGNATURES)

Wrapper around `LibSSH.lib.ssh_userauth_list()`. It will throw a
`LibSSHException` if the SSH server supports `AuthMethod_None` or if another
error occurred.
"""
function userauth_list(session::Session)
    # First we have to call ssh_userauth_none() for... some reason, according to
    # the docs.
    status = userauth_none(session)
    if status == AuthStatus_Success
        throw(LibSSHException("userauth_none() succeeded when getting supported auth methods, this should not happen!"))
    end

    ret = lib.ssh_userauth_list(session.ptr, C_NULL)
    auth_methods = AuthMethod[]
    for method in instances(AuthMethod)
        if (Int(method) & ret) > 0
            push!(auth_methods, method)
        end
    end

    return auth_methods
end

"""
$(TYPEDSIGNATURES)

Wrapper around `LibSSH.lib.ssh_userauth_password()`. This will throw a
`LibSSHException` if an error is returned by the underlying library.
"""
function userauth_password(session::Session, password::String)
    while true
        GC.@preserve password begin
            password_cstr = Base.unsafe_convert(Ptr{Cchar}, password)
            ret = AuthStatus(lib.ssh_userauth_password(session.ptr, C_NULL, password_cstr))
        end

        if ret == AuthStatus_Again
            wait(session)
        elseif ret == AuthStatus_Error
            throw(LibSSHException("Got AuthStatus_Error (SSH_AUTH_ERROR) when authenticating"))
        else
            return ret
        end
    end
end
