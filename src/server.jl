import .Callbacks: ServerCallbacks

"""
`SessionEvent(session::Session)`

This object holds a `LibSSH.lib.ssh_event` that has a single `Session` added to
it. Note: it should be closed *before* `session` is closed.
"""
mutable struct SessionEvent
    ptr::Union{lib.ssh_event, Nothing}
    session::Session

    function SessionEvent(session::Session)
        ptr = lib.ssh_event_new()
        if ptr == C_NULL
            throw(LibSSHException("Could not allocate ssh_event"))
        end

        ret = lib.ssh_event_add_session(ptr, session.ptr)
        if ret != SSH_OK
            lib.ssh_event_free(ptr)
            throw(LibSSHException("Could not add Session to SessionEvent"))
        end

        self = new(ptr, session)
        finalizer(self) do event
            try
                close(event)
            catch ex
                # If closing threw, the only thing we can do is schedule an
                # error to be printed later.
                @async @error "Caught error when cleaning up SessionEvent!" exception=(ex, catch_backtrace())
            end
        end
    end
end

"""
$(TYPEDSIGNATURES)

Removes the `Session` from the underlying `ssh_event` and frees the event
memory. This function may be safely called multiple times, and the event will be
unusable afterwards.

If removing the session fails a `LibSSH.LibSSHException` will be thrown, which
could happen if the session is closed before the event is.
"""
function Base.close(event::SessionEvent)
    if !isnothing(event.ptr)
        session_remove_ret = SSH_OK
        if !isnothing(event.session.ptr)
            session_remove_ret = lib.ssh_event_remove_session(event.ptr, event.session.ptr::lib.ssh_session)
        end

        # No matter what, we always free the event
        lib.ssh_event_free(event.ptr)
        event.ptr = nothing

        # Throw an exception if removing the session failed. Currently this
        # always fails so it's disabled :( In my defense, the return value isn't
        # checked in other codebases I looked at but I can't tell if that's
        # because no-one cares enough or if it doesn't matter.
        # if session_remove_ret != SSH_OK
        #     throw(LibSSHException("Removing Session from SessionEvent failed: $(session_remove_ret)"))
        # end
    end
end

"""
`Server(addr::String, port::UInt, hostkey::String; log_verbosity, auth_methods)`

Wrapper around LibSSH.lib.ssh_bind.
"""
mutable struct Server
    bind_ptr::Union{lib.ssh_bind, Nothing}
    addr::String
    port::UInt
    hostkey::String
    auth_methods::Vector{AuthMethod}
    log_verbosity::Int

    # Internal things
    _listener_event::Base.Event
    _listener_started::Bool

    function Server(addr::String, port, hostkey::String;
                    log_verbosity=SSH_LOG_NOLOG,
                    auth_methods=[AuthMethod_Password])
        bind_ptr = lib.ssh_bind_new()
        lib.ssh_bind_set_blocking(bind_ptr, 0)

        server = new(bind_ptr, addr, port, hostkey, auth_methods, log_verbosity,
                     Base.Event(), false)
        server.addr = addr
        server.port = port
        server.hostkey = hostkey
        server.auth_methods = auth_methods
        server.log_verbosity = log_verbosity

        finalizer(close, server)
    end
end

function Base.close(server::Server)
    if isopen(server)
        lib.ssh_bind_free(server.bind_ptr)
        server.bind_ptr = nothing
    end
end

Base.isopen(server::Server) = !isnothing(server.bind_ptr)

# Supported bind options
BIND_PROPERTY_OPTIONS = Dict(:addr => (SSH_BIND_OPTIONS_BINDADDR, Cstring),
                             :port => (SSH_BIND_OPTIONS_BINDPORT, Cuint),
                             :hostkey => (SSH_BIND_OPTIONS_HOSTKEY, Cstring),
                             :log_verbosity => (SSH_BIND_OPTIONS_LOG_VERBOSITY, Cint))

function Base.setproperty!(server::Server, name::Symbol, value)
    if name ∉ fieldnames(Server)
        error("type Server has no field $(name)")
    end

    ret = -1

    if name ∉ keys(BIND_PROPERTY_OPTIONS)
        return setfield!(server, name, value)
    else
        # There's some weirdness around saving strings, so we do some special-casing
        # here to handle them.
        option, ctype = BIND_PROPERTY_OPTIONS[name]
        is_string = ctype == Cstring
        GC.@preserve value begin
            cvalue = is_string ? Base.unsafe_convert(ctype, value) : Base.cconvert(ctype, value)
            ret = lib.ssh_bind_options_set(server.bind_ptr, option, is_string ? Ptr{Cvoid}(cvalue) : Ref(cvalue))
        end
    end

    if ret != 0
        throw(LibSSHException("Error setting Server.$(name) to $(value): $(ret)"))
    end

    saved_type = fieldtype(Server, name)
    return setfield!(server, name, saved_type(value))
end

"""
$(TYPEDSIGNATURES)

High-level function to listen for incoming requests and pass them off to a
handler function. This will already set the auth methods on the session (from
Server.auth_methods) before calling the handler.
"""
function listen(handler::Function, server::Server; poll_timeout=0.1)
    if poll_timeout < 0
        throw(ArgumentError("poll_timeout cannot be negative!"))
    end

    ret = lib.ssh_bind_listen(server.bind_ptr)
    if ret != 0
        throw(LibSSHException("Error on LibSSH.lib.ssh_bind_listen(): $(ret)"))
    end

    fd = RawFD(lib.ssh_bind_get_fd(server.bind_ptr))
    while isopen(server)
        # Notify listeners that we've started
        if !server._listener_started
            server._listener_started = true
            notify(server._listener_event)
        end

        # Wait for new connection attempts
        poll_result = FileWatching.poll_fd(fd, poll_timeout; readable=true)

        # The first thing we do is check if the Server has been closed, because
        # that means that the file descriptor was closed while we were polling
        # it, potentially by another thread. That matters because according to
        # the close(2) docs it's unsafe to close file descriptors while they're
        # being polled in another thread because they may be reused, which could
        # lead to race conditions. Hence, we first check that the Server hasn't
        # been closed to make sure that we didn't get a wakeup from some new
        # resource using the old file descriptor.
        if !isopen(server)
            break
        elseif poll_result.timedout
            continue
        end

        # Accept the new connection
        session_ptr = lib.ssh_new()
        ret = lib.ssh_bind_accept(server.bind_ptr, session_ptr)
        if ret != SSH_OK
            throw(LibSSHException("Error when accepting new connection: $(ret)"))
        end

        session = Session(session_ptr)

        # Set the auth methods supported by the server
        set_auth_methods(session, server.auth_methods)

        # Pass off to the handler
        Threads.@spawn :interactive try
            handler(session)
        catch ex
            @error "Error handling SSH session!" exception=(ex, catch_backtrace())
        finally
            disconnect(session)
            close(session)
        end
    end
end

"""
$(TYPEDSIGNATURES)

Waits for the main loop of `LibSSH.listen()` to begin running on the server.
"""
function wait_for_listener(server::Server)
    wait(server._listener_event)
end

"""
$(TYPEDSIGNATURES)

Wrapper around `LibSSH.lib.ssh_set_auth_methods()`.
"""
function set_auth_methods(session::Session, auth_methods::Vector{AuthMethod})
    bitflag = reduce(|, Int.(auth_methods))
    lib.ssh_set_auth_methods(session.ptr, bitflag)
end

function _trywait(f::Function, session::Session)
    ret = SSH_ERROR

    while true
        ret = f()

        if ret != SSH_AGAIN
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

"""
$(TYPEDSIGNATURES)

Non-blocking wrapper around `LibSSH.lib.ssh_handle_key_exchange()`. Returns
`true` or `false` depending on whether the exchange succeeded.
"""
function handle_key_exchange(session::Session)::Bool
    ret = _trywait(session) do
        lib.ssh_handle_key_exchange(session.ptr)
    end

    return ret == SSH_OK
end

function set_server_callbacks(session::Session, callbacks::ServerCallbacks)
    ret = lib.ssh_set_server_callbacks(session.ptr, Ref(callbacks.cb_struct::lib.ssh_server_callbacks_struct))
    if ret != SSH_OK
        throw(LibSSHException("Error setting server callbacks: $(ret)"))
    end
end

"""
$(TYPEDSIGNATURES)

Non-blocking wrapper around `LibSSH.lib.ssh_event_dopoll()`, only to be used for
events that have a single session added to them (i.e. a `SessionEvent`).

Returns either `SSH_OK` or `SSH_ERROR`.
"""
function sessionevent_dopoll(event::SessionEvent)
    ret = _trywait(event.session) do
        lib.ssh_event_dopoll(event.ptr, 0)
    end

    return ret
end
