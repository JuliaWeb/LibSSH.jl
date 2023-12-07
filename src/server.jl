import .Callbacks: ServerCallbacks


"""
`SshEvent(session::Session)`

This object holds a `LibSSH.lib.ssh_event` that has a single `Session` added to
it. Note: it should be closed *before* `session` is closed.
"""
mutable struct SshEvent
    ptr::Union{lib.ssh_event, Nothing}

    function SshEvent()
        ptr = lib.ssh_event_new()
        if ptr == C_NULL
            throw(LibSSHException("Could not allocate ssh_event"))
        end

        self = new(ptr)
        finalizer(close, self)
    end
end

"""
$(TYPEDSIGNATURES)

Wrapper around `LibSSH.lib.ssh_event_add_session()`. Warning: the session should
be removed from the event before the event is closed!
"""
function event_add_session(event::SshEvent, session::Session)
    ret = lib.ssh_event_add_session(event.ptr, session.ptr)
    if ret != SSH_OK
        throw(LibSSHException("Could not add Session to SshEvent: $(ret)"))
    end
end

"""
$(TYPEDSIGNATURES)

Wrapper around `LibSSH.lib.ssh_event_remove_session()`.
"""
function event_remove_session(event::SshEvent, session::Session)
    ret = lib.ssh_event_remove_session(event.ptr, session.ptr)
    if ret != SSH_OK
        throw(LibSSHException("Could not remove Session from SshEvent: $(ret)"))
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
function Base.close(event::SshEvent)
    if !isnothing(event.ptr)
        lib.ssh_event_free(event.ptr)
        event.ptr = nothing
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
    hostkey::Union{String, Nothing}
    key::Union{PKI.SshKey, Nothing}
    auth_methods::Vector{AuthMethod}
    log_verbosity::Int

    # Internal things
    _listener_event::Base.Event
    _listener_started::Bool
    _lock::ReentrantLock

    function Server(port, addr="0.0.0.0";
                    hostkey=nothing,
                    key=nothing,
                    log_verbosity=SSH_LOG_NOLOG,
                    auth_methods=[AuthMethod_Password])
        if isnothing(hostkey) && isnothing(key)
            throw(ArgumentError("Server requires either `hostkey` or `key` to be set"))
        elseif !isnothing(hostkey) && !isnothing(key)
            throw(ArgumentError("Cannot pass both `hostkey` and `key` to Server"))
        end

        bind_ptr = lib.ssh_bind_new()
        lib.ssh_bind_set_blocking(bind_ptr, 0)

        server = new(bind_ptr, addr, port, hostkey, key, auth_methods, log_verbosity,
                     Base.Event(), false, ReentrantLock())
        server.addr = addr
        server.port = port
        if !isnothing(hostkey)
            server.hostkey = hostkey
        end
        if !isnothing(key)
            server.key = key
        end
        server.auth_methods = auth_methods
        server.log_verbosity = log_verbosity

        finalizer(server) do server
            close(server)

            # When a SshKey (lib.ssh_key) is added to a lib.ssh_bind,
            # lib.ssh_bind_free() will automatically free the key. This means
            # that when the SshKey finalizer is executed it will attempt to do a
            # double-free, causing a segfault. We get around that by manually
            # setting SshKey.ptr to nothing to tell its finalizer the memory has
            # already been free'd.
            if !isnothing(server.key)
                server.key.ptr = nothing
            end
        end
    end
end

"""
$(TYPEDSIGNATURES)

Close and free the server.
"""
function Base.close(server::Server)
    if isopen(server)
        lib.ssh_bind_free(server.bind_ptr)
        server.bind_ptr = nothing
    end
end

"""
$(TYPEDSIGNATURES)

Lock a server for thread-safe operations.
"""
Base.lock(server::Server) = lock(server._lock)

"""
$(TYPEDSIGNATURES)

Unlock a server.
"""
Base.unlock(server::Server) = unlock(server._lock)

"""
$(TYPEDSIGNATURES)

Check if the server has been free'd yet.
"""
Base.isopen(server::Server) = !isnothing(server.bind_ptr)

"""
$(TYPEDSIGNATURES)

Get the last error set by libssh.
"""
function get_error(server::Server)
    if isnothing(server.bind_ptr)
        throw(ArgumentError("Server data has been free'd, cannot get its error"))
    end

    ret = lib.ssh_get_error(Ptr{Cvoid}(server.bind_ptr))
    return unsafe_string(ret)
end

# Supported bind options
BIND_PROPERTY_OPTIONS = Dict(:addr => (SSH_BIND_OPTIONS_BINDADDR, Cstring),
                             :port => (SSH_BIND_OPTIONS_BINDPORT, Cuint),
                             :hostkey => (SSH_BIND_OPTIONS_HOSTKEY, Cstring),
                             :key => (SSH_BIND_OPTIONS_IMPORT_KEY, lib.ssh_key),
                             :log_verbosity => (SSH_BIND_OPTIONS_LOG_VERBOSITY, Cint))

# Helper function to get the types in a Union
union_types(x::Union) = (x.a, union_types(x.b)...)
union_types(x::Type) = (x,)

function Base.setproperty!(server::Server, name::Symbol, value)
    @lock server begin
        if name ∉ fieldnames(Server)
            error("type Server has no field $(name)")
        end

        ret = -1

        if name ∉ keys(BIND_PROPERTY_OPTIONS)
            return setfield!(server, name, value)
        else
            # We don't allow 'unsetting' options, that would be too complicated to implement
            if isnothing(value)
                throw(ArgumentError("Setting Server options to nothing is unsupported"))
            end

            # There's some weirdness around saving strings, so we do some special-casing
            # here to handle them.
            option, ctype = BIND_PROPERTY_OPTIONS[name]
            is_string = ctype == Cstring
            GC.@preserve value begin
                cvalue = if is_string
                    Ptr{Cvoid}(Base.unsafe_convert(ctype, value))
                elseif value isa PKI.SshKey
                    value.ptr
                else
                    Ref(Base.cconvert(ctype, value))
                end

                ret = lib.ssh_bind_options_set(server.bind_ptr, option, cvalue)
            end
        end

        if ret != 0
            throw(LibSSHException("Error setting Server.$(name) to $(value): $(ret)"))
        end

        # Get the type of the field in the struct. Some of them are unions, in which
        # case we select the first non-Nothing type in the Union. If the saved type
        # doesn't match the type of the passed value, we convert it.
        final_value = value
        saved_type = fieldtype(Server, name)
        if saved_type isa Union
            possible_types = filter(!=(Nothing), union_types(saved_type))
            saved_type = possible_types[1]
        end
        if !(value isa saved_type)
            final_value = saved_type(value)
        end

        return setfield!(server, name, final_value)
    end
end

"""
$(TYPEDSIGNATURES)

High-level function to listen for incoming requests and pass them off to a
handler function. This will already set the auth methods on the session (from
Server.auth_methods) before calling the handler.

The `poll_timeout` argument refers to the timeout for polling the server
socket for new connections. It must be >0 because otherwise it would never wake
up if the socket was closed while waiting, but other than that the exact value
doesn't matter much. It'll only control how frequently the listen loop wakes up
to check if the server has been closed yet.
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

        # Wait for new connection attempts. Note that there's a race condition
        # between the loop condition evaluation and this line, so we wrap
        # poll_fd() in a try-catch in case the server (and thus the file
        # descriptor) has been closed in the meantime, which would cause
        # poll_fd() to throw an IOError.
        local poll_result
        try
            poll_result = FileWatching.poll_fd(fd, poll_timeout; readable=true)
        catch ex
            if ex isa Base.IOError
                continue
            else
                rethrow()
            end
        end

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

"""
Helper function to aid with calling non-blocking functions. It will try calling
`f()` as long as `f()` returns `SSH_AGAIN`.
"""
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

"""
$(TYPEDSIGNATURES)

Set callbacks for a Session. Wrapper around `LibSSH.lib.ssh_set_server_callbacks()`.
"""
function set_server_callbacks(session::Session, callbacks::ServerCallbacks)
    ret = lib.ssh_set_server_callbacks(session.ptr, Ref(callbacks.cb_struct::lib.ssh_server_callbacks_struct))
    if ret != SSH_OK
        throw(LibSSHException("Error setting server callbacks: $(ret)"))
    end
end

"""
$(TYPEDSIGNATURES)

Non-blocking wrapper around `LibSSH.lib.ssh_event_dopoll()`, only to be used for
events that have a single session added to them (i.e. a `SshEvent`). All of the
channel locks passed in `sshchan_locks` will be locked while
`lib.ssh_event_dopoll()` executes (but unlocked while waiting).

Returns either `SSH_OK` or `SSH_ERROR`.
"""
function event_dopoll(event::SshEvent, session::Session, sshchan_locks...)
    ret = _trywait(session) do
        lock.(sshchan_locks)
        ret = lib.ssh_event_dopoll(event.ptr, 0)
        unlock.(sshchan_locks)

        return ret
    end

    return ret
end


module Test

import Printf: @printf

using DocStringExtensions

import ...LibSSH as ssh
import ...LibSSH.PKI as pki
import ..Server
import ..Callbacks.ServerCallbacks
import ..Callbacks.ChannelCallbacks


function exec_command(command, sshchan)
    cmd_stdout = IOBuffer()
    cmd_stderr = IOBuffer()

    result = run(pipeline(`sh -c $command`; stdout=cmd_stdout, stderr=cmd_stderr))
    write(sshchan, String(take!(cmd_stdout)))
    write(sshchan, String(take!(cmd_stderr)); stderr=true)
    ssh.channel_request_send_exit_status(sshchan, result.exitcode)
    ssh.channel_send_eof(sshchan)
    close(sshchan)
end

function on_auth_password(session, user, password, test_server)::ssh.AuthStatus
    _add_log_event!(test_server, :auth_password, (user, password))

    return password == test_server.password ? ssh.AuthStatus_Success : ssh.AuthStatus_Denied
end

function on_auth_none(session, user, test_server)::ssh.AuthStatus
    _add_log_event!(test_server, :auth_none, true)
    return ssh.AuthStatus_Denied
end

function on_service_request(session, service, test_server)::Bool
    _add_log_event!(test_server, :service_request, service)
    return true
end

function on_channel_open(session, test_server)::Union{ssh.SshChannel, Nothing}
    _add_log_event!(test_server, :channel_open, true)
    sshchan = ssh.SshChannel(session)
    test_server.sshchan = sshchan
    return sshchan
end

function on_channel_write_wontblock(session, sshchan, n_bytes, test_server)::Int
    _add_log_event!(test_server, :channel_write_wontblock, n_bytes)
    return 0
end

function on_channel_env_request(session, sshchan, name, value, test_server)::Bool
    _add_log_event!(test_server, :channel_env_request, (name, value))
    return true
end

function on_channel_exec_request(session, sshchan, command, test_server)::Bool
    _add_log_event!(test_server, :channel_exec_request, command)

    # Note that we ignore the `sshchan` argument in favour of
    # `test_server.sshchan`. That's extremely important! `sshchan` is a
    # non-owning SshChannel created by the callback over the underlying
    # lib.ssh_channel pointer, which means that `sshchan` and
    # `test_server.sshchan` are two distinct Julia objects with pointers to the
    # same lib.ssh_channel struct.
    #
    # If we were to pass `sshchan` instead, exec_command() would attempt to
    # close `sshchan`, which would free the underlying lib.ssh_channel, which
    # would cause a double-free later when we close
    # `test_server.sshchan`. That's why close()'ing non-owning SshChannels is
    # forbidden.
    Threads.@spawn exec_command(command, test_server.sshchan)
    return true
end

function on_channel_eof(session, sshchan, test_server)::Nothing
    _add_log_event!(test_server, :channel_eof, true)
    return nothing
end

function on_channel_close(session, sshchan, test_server)::Nothing
    _add_log_event!(test_server, :channel_close, true)
    close(test_server.sshchan)
end

function handle_session(session, ts)
    empty!(ts.callback_log)
    for callback_sym in keys(merge(ts.server_callbacks.functions,
                                   ts.channel_callbacks.functions))
        ts.callback_log[callback_sym] = []
    end

    ssh.set_server_callbacks(session, ts.server_callbacks)
    if !ssh.handle_key_exchange(session)
        @error "Key exchange failed"
        return
    end

    event = ssh.SshEvent()
    ssh.event_add_session(event, session)
    while isnothing(ts.sshchan)
        ret = ssh.event_dopoll(event, session)

        if ret != ssh.SSH_OK
            break
        end
    end

    if !isnothing(ts.sshchan)
        ssh.Callbacks.set_channel_callbacks(ts.sshchan, ts.channel_callbacks)
        while ssh.event_dopoll(event, session, ts.sshchan.close_lock) == ssh.SSH_OK
            continue
        end

        close(ts.sshchan)
    end

    try
        ssh.event_remove_session(event, session)
    catch ex
        # This is commented out because it doesn't seem to be a critical
        # error. Worth investigating in the future though.
        # @error "Error removing session from event" exception=ex
    end

    close(event)
end

@kwdef mutable struct TestServer
    server::Server
    server_callbacks::ServerCallbacks = ServerCallbacks()
    channel_callbacks::ChannelCallbacks = ChannelCallbacks()
    listener_task::Union{Task, Nothing} = nothing
    sshchan::Union{ssh.SshChannel, Nothing} = nothing
    verbose::Bool = false
    password::Union{String, Nothing} = nothing

    callback_log::Dict{Symbol, Vector} = Dict{Symbol, Vector}()
    log_timeline::Vector = []
    log_lock::ReentrantLock = ReentrantLock()
    log_id::Int = 1
end

"""
$(TYPEDSIGNATURES)
"""
function TestServer(port::Int; verbose=false, password=nothing,
                    auth_methods=[ssh.AuthMethod_None, ssh.AuthMethod_Password])
    if ssh.AuthMethod_Password in auth_methods && isnothing(password)
        throw(ArgumentError("You must pass `password` to TestServer since password authentication is enabled"))
    end

    key = pki.generate(pki.KeyType_ed25519)
    server = ssh.Server(port; auth_methods, key)

    test_server = TestServer(; server, verbose, password)

    test_server.server_callbacks = ServerCallbacks(test_server;
                                                   auth_password_function=on_auth_password,
                                                   auth_none_function=on_auth_none,
                                                   service_request_function=on_service_request,
                                                   channel_open_request_session_function=on_channel_open)
    test_server.channel_callbacks = ChannelCallbacks(test_server;
                                                     channel_eof_function=on_channel_eof,
                                                     channel_close_function=on_channel_close,
                                                     channel_exec_request_function=on_channel_exec_request,
                                                     channel_env_request_function=on_channel_env_request,
                                                     channel_write_wontblock_function=on_channel_write_wontblock)

    return test_server
end

"""
$(TYPEDSIGNATURES)

Do-constructor to execute a function while the server is running and have it
safely cleaned up afterwards.
"""
function TestServer(f::Function, args...; kwargs...)
    test_server = TestServer(args...; kwargs...)
    start(test_server)

    try
        f()
    finally
        stop(test_server)
    end

    return test_server
end

function start(test_server::TestServer)
    handle_wrapper = session -> handle_session(session, test_server)
    test_server.listener_task = Threads.@spawn ssh.listen(handle_wrapper, test_server.server)
    ssh.wait_for_listener(test_server.server)
end

function stop(test_server::TestServer)
    if !isnothing(test_server.listener_task)
        close(test_server.server)
        wait(test_server.listener_task)
        test_server.listener_task = nothing
    end
end

function _add_log_event!(ts::TestServer, callback_name::Symbol, event)
    @lock ts.log_lock begin
        log_vector = ts.callback_log[callback_name]
        push!(log_vector, event)
        push!(ts.log_timeline, (callback_name, lastindex(log_vector), time()))

        if ts.verbose
            @info "$callback_name $event"
            flush(stdout)
        end
    end
end

"""
$(TYPEDSIGNATURES)

Print a nicely formatted timeline of callbacks and their logged data.
"""
function print_timeline(ts::TestServer)
    duration = ts.log_timeline[end][3] - ts.log_timeline[1][3]
    @printf("%d callbacks in %.3fs\n", length(ts.log_timeline), duration)

    for (id, (callback_name, log_idx, _)) in enumerate(ts.log_timeline)
        @printf("%-4d %-30s %s\n",
                id,
                callback_name,
                string(ts.callback_log[callback_name][log_idx]))
    end
end

end
