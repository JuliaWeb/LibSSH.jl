# Represents a keyboard-interactive prompt from a server
struct KbdintPrompt
    msg::String
    display::Bool
end

"""
$(TYPEDEF)
$(TYPEDFIELDS)

Represents an SSH session. Note that some properties such as the host and port are
implemented in `getproperty()`/`setproperty!()` by using the internal values of
the `ssh_session`, i.e. they aren't simply fields of the struct. A `Session` may
be owning or non-owning of its internal pointer to a `lib.ssh_session`.
"""
mutable struct Session
    ptr::Union{lib.ssh_session, Nothing}
    owning::Bool
    log_verbosity::Int
    channels::Vector{Any}
    server_callbacks::Union{Callbacks.ServerCallbacks, Nothing}

    @doc """
    $(TYPEDSIGNATURES)

    This is only useful if you already have a `ssh_session` (i.e. in a
    server). Do not use it if you want a client, use the other constructor.

    # Arguments
    - `ptr`: A pointer to the `lib.ssh_session` to wrap.
    - `log_verbosity=nothing`: Set the log verbosity for the
       session. This argument will be ignored if `own` is `false` to avoid
       accidentally changing the logging level in callbacks when non-owning
       Sessions are created. You can still set the logging level explicitly with
       `session.log_verbosity` if necessary.
    - `own=true`: Whether to take ownership of `ptr`, i.e. whether
      to register a finalizer to free the memory.
    """
    function Session(ptr::lib.ssh_session; log_verbosity=nothing, own::Bool=true)
        # Set to non-blocking mode
        lib.ssh_set_blocking(ptr, 0)

        session = new(ptr, own, -1, [], nothing)
        if !isnothing(log_verbosity)
            session.log_verbosity = log_verbosity
        end

        if own
            finalizer(_finalizer, session)
        end

        return session
    end
end

function Base.show(io::IO, session::Session)
    if isopen(session)
        print(io, Session, "(host=$(session.host), port=$(session.port), user=$(session.user), connected=$(isconnected(session)))")
    else
        print(io, Session, "()")
    end
end

# Non-throwing finalizer for Session objects
function _finalizer(session::Session)
    try
        close(session)
    catch ex
        Threads.@spawn @error "Error when finalizing Session" exception=(ex, catch_backtrace())
    end
end

"""
$(TYPEDSIGNATURES)

Constructor for creating a client session. Use this if you want to connect to a
server.

# Throws
- [`LibSSHException`](@ref): if a session couldn't be created, or there was an
  error initializing the `user` property.

# Arguments
- `host`: The host to connect to.
- `port=22`: The port to connect to.
- `user=nothing`: Set the user to connect as. If unset the current
   username will be used.
- `log_verbosity=nothing`: Set the log verbosity for the session.
- `auto_connect=true`: Whether to automatically call
  [`connect()`](@ref).

# Examples

```julia-repl
julia> import LibSSH as ssh
julia> session = ssh.Session("foo.org")
julia> session = ssh.Session(ip"12.34.56.78", 2222)
```
"""
function Session(host::Union{AbstractString, Sockets.IPAddr}, port=22;
                 user=nothing, log_verbosity=nothing, auto_connect=true)
    session_ptr = lib.ssh_new()
    if session_ptr == C_NULL
        throw(LibSSHException("Could not initialize Session for host $(host)"))
    end

    host_str = host isa AbstractString ? host : string(host)

    session = Session(session_ptr; log_verbosity)
    session.host = host_str
    session.port = port

    if isnothing(user)
        # Explicitly initialize the user, otherwise an error will be thrown when
        # retrieving it. Passing null will set it to the current user (see docs).
        ret = ssh_options_set(session.ptr, SSH_OPTIONS_USER, C_NULL)
        if ret != 0
            throw(LibSSHException("Error when initializing user: $(ret)"))
        end
    else
        session.user = user
    end

    if auto_connect
        connect(session)
    end

    return session
end

"""
$(TYPEDSIGNATURES)

Check if the `Session` holds a valid pointer to a `lib.ssh_session`. This will
be `false` if the session has been closed.
"""
Base.isassigned(session::Session) = !isnothing(session.ptr)

"""
$(TYPEDSIGNATURES)

Closes a session, which will be unusable afterwards. It's safe to call this
multiple times.

# Throws
- `ArgumentError`: If the session is non-owning. This is not allowed to prevent
  accidental double-frees.
"""
function Base.close(session::Session)
    if !session.owning
        throw(ArgumentError("Calling close() on a non-owning Session is not allowed to avoid accidental double-frees, see the docs for more information."))
    end

    if isopen(session)
        disconnect(session)
        lib.ssh_free(session.ptr)
        session.ptr = nothing
    end
end

"""
$(TYPEDSIGNATURES)

Check if a session is open.
"""
Base.isopen(session::Session) = isassigned(session) # We currently don't allow closed sessions

"""
$(TYPEDSIGNATURES)

Get the last error set by libssh.

# Throws
- `ArgumentError`: If the session has been closed.

Wrapper around [`lib.ssh_get_error()`](@ref).
"""
function get_error(session::Session)
    if !isassigned(session)
        throw(ArgumentError("Session has been free'd, cannot get its error"))
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
    (:host, :port, :user, :log_verbosity, :owning, (private ? (:ptr, :channels, :server_callbacks) : ())...)
end

function Base.getproperty(session::Session, name::Symbol)
    if name ∉ propertynames(session, true)
        error("type Session has no field $(name)")
    end

    # If it's a property that we save, then we return the saved value
    if name in fieldnames(Session) || name in SAVED_PROPERTIES
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

    if name == :ptr || name == :server_callbacks
        return setfield!(session, name, value)
    end

    # There's some weirdness around saving strings, so we do some special-casing
    # here to handle them.
    option, ctype = SESSION_PROPERTY_OPTIONS[name]
    is_string = ctype == Cstring

    # Always convert string values to String, types like SubString cannot be
    # converted to Cstring.
    if is_string
        value_str = String(value)
        GC.@preserve value_str begin
            cvalue = Base.unsafe_convert(ctype, value_str)
            ret = ssh_options_set(session.ptr, option, Ptr{Cvoid}(cvalue))
        end
    else
        GC.@preserve value begin
            cvalue = Base.cconvert(ctype, value)
            ret = ssh_options_set(session.ptr, option, Ref(cvalue))
        end
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

The `poll_timeout` argument has the same meaning as [`listen(::Function,
::Bind)`](@ref).
"""
function Base.wait(session::Session; poll_timeout=0.1)
    if poll_timeout <= 0
        throw(ArgumentError("poll_timeout=$(poll_timeout), it must be greater than 0"))
    end

    if lib.ssh_is_blocking(session.ptr) == 1
        return
    end

    poll_flags = lib.ssh_get_poll_flags(session.ptr)
    readable = (poll_flags & lib.SSH_READ_PENDING) > 0
    writable = (poll_flags & lib.SSH_WRITE_PENDING) > 0

    fd = RawFD(lib.ssh_get_fd(session.ptr))
    while isopen(session)
        result = _safe_poll_fd(fd, poll_timeout; readable, writable)
        if isnothing(result)
            # This means the session's file descriptor has been closed (see the
            # comments for _safe_poll_fd()).
            continue
        elseif !result.timedout
            break
        end
    end

    return nothing
end

"""
$(TYPEDSIGNATURES)

This will throw an exception if connecting fails. You shouldn't need this unless
you've created a session with `Session(; auto_connect=false)`.

Wrapper around [`lib.ssh_connect()`](@ref).
"""
function connect(session::Session)
    if !isassigned(session)
        throw(ArgumentError("Session has been closed, cannot connect it to a server"))
    elseif isconnected(session)
        return
    end

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

Wrapper around [`lib.ssh_disconnect()`](@ref).

!!! warning
    This will close all channels created from the session.
"""
function disconnect(session::Session)
    if isconnected(session)
        # We close all the channels in reverse order because close(::SshChannel)
        # deletes each channel from the vector and we don't want to invalidate
        # any indices while deleting. The channels need to be closed here
        # because lib.ssh_disconnect() will free all of them.
        for i in reverse(eachindex(session.channels))
            # Note that only owning channels are added to session.channels, which
            # means that this should never throw because the channel is non-owning
            # (of course it may still throw for other reasons).
            close(session.channels[i])
        end

        lib.ssh_disconnect(session.ptr)
    end
end

"""
$(TYPEDSIGNATURES)

Wrapper around [`lib.ssh_is_connected()`](@ref).
"""
function isconnected(session::Session)
    isassigned(session) ? lib.ssh_is_connected(session.ptr) == 1 : false
end

"""
$(TYPEDSIGNATURES)

Get the public key from server of a connected session.

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error.

Wrapper around [`lib.ssh_get_server_publickey()`](@ref).
"""
function get_server_publickey(session::Session)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot get the servers public key"))
    end

    key_ref = Ref{lib.ssh_key}()
    ret = lib.ssh_get_server_publickey(session.ptr, key_ref)
    if ret != SSH_OK
        throw(LibSSHException("Error when getting servers public key: $(ret)"))
    end

    return PKI.SshKey(key_ref[])
end

"""
$(TYPEDSIGNATURES)

Check if the connected servers public key exists in the SSH known hosts
file.

# Throws
- `ArgumentError`: If the session isn't connected.
- [`HostVerificationException`](@ref): If verification failed and
  `throw_on_failure` is `true`.

# Arguments
- `throw_on_failure=true`: Whether to throw a
  [`HostVerificationException`](@ref) if the verification fails, otherwise the
  function will just return the verification status.

Wrapper around [`lib.ssh_session_is_known_server()`](@ref).
"""
function is_known_server(session::Session; throw_on_failure=true)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot check the servers public key"))
    end

    status = KnownHosts(Int(lib.ssh_session_is_known_server(session.ptr)))
    if throw_on_failure && status != KnownHosts_Ok
        throw(HostVerificationException(status))
    end

    return status
end

"""
$(TYPEDSIGNATURES)

Update the users known hosts file with the sessions server key.

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error.

Wrapper around [`lib.ssh_session_update_known_hosts()`](@ref).
"""
function update_known_hosts(session::Session)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot get the servers public key to update the known hosts file"))
    end

    ret = lib.ssh_session_update_known_hosts(session.ptr)
    if ret != SSH_OK
        throw(LibSSHException("Could not update the users known hosts file: $(ret)"))
    end
end

"""
$(TYPEDSIGNATURES)

Attempt to authenticate to the server without any credentials. This
authentication method is always disabled in practice, but it's still useful to
check which authentication methods the server supports (see
[`userauth_list()`](@ref)).

# Arguments
- `session`: The session to authenticate.
- `throw_on_error=true`: Whether to throw if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error, unless `throw_on_error=false`.

Wrapper around [`lib.ssh_userauth_none()`](@ref).
"""
function userauth_none(session::Session; throw_on_error=true)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    while true
        ret = AuthStatus(lib.ssh_userauth_none(session.ptr, C_NULL))

        if ret == AuthStatus_Again
            wait(session)
        elseif ret == AuthStatus_Error && throw_on_error
            throw(LibSSHException("Got AuthStatus_Error (SSH_AUTH_ERROR) when calling userauth_none()"))
        else
            return ret
        end
    end
end

"""
$(TYPEDSIGNATURES)

Get a list of support authentication methods from the server. This will
automatically call [`userauth_none()`](@ref) beforehand.

# Throws
- `ArgumentError`: If the session isn't connected.

Wrapper around [`lib.ssh_userauth_list()`](@ref).
"""
function userauth_list(session::Session)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    # First we have to call ssh_userauth_none() for... some reason, according to
    # the docs.
    status = userauth_none(session)

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

Authenticate by username and password. The username will be taken from
`session.user`.

# Arguments
- `session`: The session to authenticate.
- `password`: The password to authenticate with.
- `throw_on_error=true`: Whether to throw_on_error if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error, unless `throw_on_error=false`.

Wrapper around [`lib.ssh_userauth_password()`](@ref).
"""
function userauth_password(session::Session, password::String; throw_on_error=true)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    while true
        GC.@preserve password begin
            password_cstr = Base.unsafe_convert(Ptr{Cchar}, password)
            ret = AuthStatus(lib.ssh_userauth_password(session.ptr, C_NULL, password_cstr))
        end

        if ret == AuthStatus_Again
            wait(session)
        elseif ret == AuthStatus_Error && throw_on_error
            throw(LibSSHException("Got AuthStatus_Error (SSH_AUTH_ERROR) when authenticating"))
        else
            return ret
        end
    end
end

"""
$(TYPEDSIGNATURES)

Authenticate with GSSAPI. This is not available on all platforms (see
[`Gssapi.isavailable()`](@ref)).

# Arguments
- `session`: The session to authenticate.
- `throw_on_error=true`: Whether to throw if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected.
- `ErrorException`: If GSSAPI support isn't available.
- `LibSSHException`: If there was an internal error, unless `throw_on_error=false`.

Wrapper around [`lib.ssh_userauth_gssapi()`](@ref).
"""
function userauth_gssapi(session::Session; throw_on_error=true)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    elseif !Gssapi.isavailable()
        error("GSSAPI support is not available")
    end

    ret = _session_trywait(session) do
        lib.ssh_userauth_gssapi(session.ptr)
    end
    status = AuthStatus(ret)

    if status == AuthStatus_Error && throw_on_error
        throw(LibSSHException("Got AuthStatus_Error (SSH_AUTH_ERROR) when authenticating"))
    end

    return status
end

"""
$(TYPEDSIGNATURES)

Attempt to authenticate with the keyboard-interactive method.

# Arguments
- `session`: The session to authenticate.
- `throw_on_error=true`: Whether to throw if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error, unless `throw_on_error=false`.

Wrapper around [`lib.ssh_userauth_kbdint`](@ref).
"""
function userauth_kbdint(session::Session; throw_on_error=true)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    ret = _session_trywait(session) do
        lib.ssh_userauth_kbdint(session.ptr, C_NULL, C_NULL)
    end
    status = AuthStatus(ret)

    if status == AuthStatus_Error && throw_on_error
        throw(LibSSHException("Got AuthStatus_Error (SSH_AUTH_ERROR) when authenticating"))
    end

    return status
end

"""
$(TYPEDSIGNATURES)

Returns all the keyboard-interactive prompts from the server. You should have
already called [`userauth_kbdint()`](@ref). The `KbdintPrompt` objects it
returns have `.msg` and `.display` fields that hold the prompt message and
whether to echo the user input (e.g. it will be `false` for a password and other
sensitive input).

This is a combination of [`lib.ssh_userauth_kbdint_getnprompts`](@ref) and
[`lib.userauth_kbdint_getprompt`](@ref). It should be preferred over the
lower-level functions.

# Throws
- `ArgumentError`: If the session isn't connected.
"""
function userauth_kbdint_getprompts(session::Session)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    prompts = KbdintPrompt[]
    n_prompts = lib.ssh_userauth_kbdint_getnprompts(session.ptr)
    for i in 0:n_prompts - 1
        echo_ref = Ref{Cchar}()
        question = lib.userauth_kbdint_getprompt(session.ptr, i, echo_ref)
        push!(prompts, KbdintPrompt(question, Bool(echo_ref[])))
    end

    return prompts
end

"""
$(TYPEDSIGNATURES)

Sets answers for a keyboard-interactive auth session. Uses
[`lib.ssh_userauth_kbdint_setanswer`](@ref) internally.

# Arguments
- `session`: The session to authenticate.
- `answers`: A vector of answers for each prompt sent by the server.

# Throws
- `ArgumentError`: If the session isn't connected, or if the wrong number of
  answers were passed.
- `LibSSHException`: If setting the answers failed.
"""
function userauth_kbdint_setanswers(session::Session, answers::Vector{String})
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    n_prompts = lib.ssh_userauth_kbdint_getnprompts(session.ptr)
    if n_prompts != length(answers)
        throw(ArgumentError("Server sent $(n_prompts) prompts, but was passed $(length(answers)) answers"))
    end

    for (i, answer) in enumerate(answers)
        ret = lib.ssh_userauth_kbdint_setanswer(session.ptr, i - 1,
                                                Base.cconvert(Cstring, answer))
        if ret != SSH_OK
            throw(LibSSHException("Error while setting answer $(i) with ssh_userauth_kbdint_setanswer(): $(ret)"))
        end
    end
end

#=
Helper function to aid with calling non-blocking functions. It will try calling
`f()` as long as `f()` returns `SSH_AGAIN` or `SSH_AUTH_AGAIN`.
=#
function _session_trywait(f::Function, session::Session)
    ret = SSH_ERROR

    while true
        ret = f()

        if ret != SSH_AGAIN && ret != lib.SSH_AUTH_AGAIN
            break
        else
            try
                wait(session)
            catch ex
                if ex isa Base.IOError
                    # An IOError will sometimes (!) occur if the socket was
                    # closed in the middle of waiting.
                    break
                else
                    rethrow(ex)
                end
            end
        end
    end

    return ret
end
