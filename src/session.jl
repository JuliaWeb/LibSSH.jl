"""
Session(host::String)

Represents an SSH session. Note that some properties such as the host and port are
implemented in getproperty()/setproperty!() by using the internal values of
the `ssh_session`, i.e. they aren't simply fields of the struct.
"""
mutable struct Session
    ptr::Union{lib.ssh_session, Nothing}
    log_verbosity::Int

    """
    $(TYPEDSIGNATURES)
    """
    function Session(host::String; log_verbosity=SSH_LOG_WARNING)
        session_ptr = lib.ssh_new()
        if session_ptr == C_NULL
            throw(LibSSHException("Could not initialize Session for host $(host)"))
        end

        session = new(session_ptr, -1)
        session.host = host
        session.log_verbosity = log_verbosity

        # Explicitly initialize the user, otherwise an error will be thrown when
        # retrieving it. Passing null will set it to the current user (see docs).
        ret = ssh_options_set(session.ptr, SSH_OPTIONS_USER, C_NULL)
        if ret != 0
            throw(LibSSHException("Error when initializing user: $(ret)"))
        end

        finalizer(session) do s
            lib.ssh_free(s.ptr)
            s.ptr = nothing
        end
    end
end

# Mapping from option name to the corresponding enum and C type
const PROPERTY_OPTIONS = Dict(:host => (SSH_OPTIONS_HOST, Cstring),
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
        value = UInt32(port[])
    else
        # All properties supported by ssh_options_get() are strings, so we know
        # that this option must be a string.
        is_string = true
        option = PROPERTY_OPTIONS[name][1]

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
    option, ctype = PROPERTY_OPTIONS[name]
    is_string = ctype == Cstring
    GC.@preserve value begin
        cvalue = is_string ? Base.unsafe_convert(ctype, value) : Base.cconvert(ctype, value)
        ret = ssh_options_set(session.ptr, option, is_string ? Ptr{Cvoid}(cvalue) : Ref(cvalue))
    end

    if ret != 0
        throw(LibSSHException("Error setting $(name) to $(value): $(ret)"))
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

Wrapper around `LibSSH.lib.ssh_connect()`.
"""
function connect(session::Session)
    ret = lib.ssh_connect(session.ptr)
    if ret != 0
        throw(LibSSHException("Error connecting to $(session.host): $(ret)"))
    end
end

"""
$(TYPEDSIGNATURES)

Wrapper around `LibSSH.lib.ssh_disconnect()`.
"""
function disconnect(session::Session)
    lib.ssh_disconnect(session.ptr)
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
    ret = lib.ssh_userauth_none(session.ptr, C_NULL)
    if ret == SSH_AUTH_SUCCESS
        throw(LibSSHException("ssh_userauth_none() succeeded when getting supported auth methods, this should not happen!"))
    elseif ret == SSH_AUTH_ERROR
        throw(LibSSHException("Error calling ssh_userauth_none() when getting supported auth methods: $(ret)"))
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

@enum AuthStatus begin
    AuthStatus_Error = Int(SSH_AUTH_ERROR)
    AuthStatus_Denied = Int(SSH_AUTH_DENIED)
    AuthStatus_Partial = Int(SSH_AUTH_PARTIAL)
    AuthStatus_Success = Int(SSH_AUTH_SUCCESS)
    AuthStatus_Again = Int(SSH_AUTH_AGAIN)
end

"""
$(TYPEDSIGNATURES)

Wrapper around `ssh_userauth_password()`. This will throw a `LibSSHException` if a
`AuthStatus_Error` is returned by the underlying library.
"""
function userauth_password(session::Session, password::String)
    GC.@preserve password begin
        password_cstr = Base.unsafe_convert(Ptr{Cchar}, password)
        ret = lib.ssh_userauth_password(session.ptr, C_NULL, password_cstr)
    end

    if ret == AuthStatus_Error
        throw(LibSSHException("Got AuthStatus_Error when authenticating"))
    end

    return AuthStatus(ret)
end
