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

    # Settings for message callbacks
    _message_callback::Union{Function, Nothing}
    _message_callback_userdata::Any

    function Server(port, addr="0.0.0.0";
                    hostkey=nothing,
                    key=nothing,
                    log_verbosity=SSH_LOG_NOLOG,
                    auth_methods=[AuthMethod_Password],
                    message_callback::Union{Function, Nothing}=nothing,
                    message_callback_userdata=nothing)
        if isnothing(hostkey) && isnothing(key)
            throw(ArgumentError("Server requires either `hostkey` or `key` to be set"))
        elseif !isnothing(hostkey) && !isnothing(key)
            throw(ArgumentError("Cannot pass both `hostkey` and `key` to Server"))
        end

        bind_ptr = lib.ssh_bind_new()
        lib.ssh_bind_set_blocking(bind_ptr, 0)

        server = new(bind_ptr, addr, port, hostkey, key, auth_methods, log_verbosity,
                     Base.Event(), false, ReentrantLock(),
                     nothing, nothing)
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

        if !isnothing(message_callback)
            set_message_callback(message_callback, server, message_callback_userdata)
        end

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

# Wrapper around the user-defined message callback
function _message_callback_wrapper(session_ptr::lib.ssh_session, message::lib.ssh_message, server_ptr::Ptr{Cvoid})::Cint
    server::Server = unsafe_pointer_to_objref(server_ptr)
    session = Session(session_ptr; own=false)

    jl_result::Bool = true
    try
        jl_result = server._message_callback(session, message, server._message_callback_userdata)
    catch ex
        @error "Exception in message_callback!" exception=(ex, catch_backtrace())
    end

    return Cint(jl_result)
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
    if ret != SSH_OK
        # If binding fails, we wake up any waiting tasks and throw an exception
        notify(server._listener_event)
        throw(LibSSHException("Error on LibSSH.lib.ssh_bind_listen(): $(get_error(server))"))
    end

    message_callback_cfunc = @cfunction(_message_callback_wrapper,
                                        Cint,
                                        (lib.ssh_session, lib.ssh_message, Ptr{Cvoid}))

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

        # Set the message callback, if there is one
        if !isnothing(server._message_callback)
            lib.ssh_set_message_callback(session_ptr, message_callback_cfunc, pointer_from_objref(server))
        end

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
$(TYPEDSIGNATURES)

Non-blocking wrapper around `LibSSH.lib.ssh_handle_key_exchange()`. Returns
`true` or `false` depending on whether the exchange succeeded.
"""
function handle_key_exchange(session::Session)::Bool
    ret = _session_trywait(session) do
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

Set message callbacks for the sessions accepted by a Server. This must be set
before `listen()` is called to take effect. `listen()` will automatically set
the callback before passing the session to the user handler.
"""
function set_message_callback(f::Function, server::Server, userdata)
    server._message_callback = f
    server._message_callback_userdata = userdata
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
    ret = _session_trywait(session) do
        lock.(sshchan_locks)
        ret = lib.ssh_event_dopoll(event.ptr, 0)
        unlock.(sshchan_locks)

        return ret
    end

    return ret
end


module Demo

import Dates
import Printf: @printf
import Sockets
import Sockets: getaddrinfo, IPv4

using DocStringExtensions

import ...LibSSH as ssh
import ...LibSSH.lib
import ...LibSSH.PKI as pki
import ..Server
import ..Callbacks: ServerCallbacks, ChannelCallbacks


function exec_command(command, demo_server)
    sshchan = demo_server.sshchan
    cmd_stdout = IOBuffer()
    cmd_stderr = IOBuffer()

    # Start the process and wait for it
    proc = run(pipeline(ignorestatus(`sh -c $command`); stdout=cmd_stdout, stderr=cmd_stderr)
               ; wait=false)
    demo_server.exec_proc = proc
    wait(proc)

    # Write the output to the channel. We first check if the channel is open in
    # case it's been killed suddenly in the meantime.
    if isopen(sshchan)
        write(sshchan, String(take!(cmd_stdout)))
        write(sshchan, String(take!(cmd_stderr)); stderr=true)

        # Clean up
        ssh.channel_request_send_exit_status(sshchan, proc.exitcode)
        ssh.channel_send_eof(sshchan)
    end

    close(sshchan)
end

function on_auth_password(session, user, password, demo_server)::ssh.AuthStatus
    _add_log_event!(demo_server, :auth_password, (user, password))

    return password == demo_server.password ? ssh.AuthStatus_Success : ssh.AuthStatus_Denied
end

function on_auth_none(session, user, demo_server)::ssh.AuthStatus
    _add_log_event!(demo_server, :auth_none, true)
    return ssh.AuthStatus_Denied
end

function on_service_request(session, service, demo_server)::Bool
    _add_log_event!(demo_server, :service_request, service)
    return true
end

function on_channel_open(session, demo_server)::Union{ssh.SshChannel, Nothing}
    _add_log_event!(demo_server, :channel_open, true)
    sshchan = ssh.SshChannel(session)
    demo_server.sshchan = sshchan
    return sshchan
end

function on_channel_write_wontblock(session, sshchan, n_bytes, demo_server)::Int
    _add_log_event!(demo_server, :channel_write_wontblock, n_bytes)
    return 0
end

function on_channel_env_request(session, sshchan, name, value, demo_server)::Bool
    _add_log_event!(demo_server, :channel_env_request, (name, value))
    return true
end

function on_channel_exec_request(session, sshchan, command, demo_server)::Bool
    _add_log_event!(demo_server, :channel_exec_request, command)

    # Note that we ignore the `sshchan` argument in favour of
    # `demo_server.sshchan`. That's extremely important! `sshchan` is a
    # non-owning SshChannel created by the callback over the underlying
    # lib.ssh_channel pointer, which means that `sshchan` and
    # `demo_server.sshchan` are two distinct Julia objects with pointers to the
    # same lib.ssh_channel struct.
    #
    # If we were to pass `sshchan` instead, exec_command() would attempt to
    # close `sshchan`, which would free the underlying lib.ssh_channel, which
    # would cause a double-free later when we close
    # `demo_server.sshchan`. That's why close()'ing non-owning SshChannels is
    # forbidden.
    demo_server.exec_task = Threads.@spawn try
        exec_command(command, demo_server)
    catch ex
        @error "Error when running command" exception=(ex, catch_backtrace())
    end

    return true
end

function on_channel_eof(session, sshchan, demo_server)::Nothing
    _add_log_event!(demo_server, :channel_eof, true)
    return nothing
end

function on_channel_close(session, sshchan, demo_server)::Nothing
    _add_log_event!(demo_server, :channel_close, true)
    close(demo_server.sshchan)
end

function on_channel_pty_request(session, sshchan, term, width, height, pxwidth, pxheight, demo_server)::Bool
    _add_log_event!(demo_server, :channel_pty_request, (term, width, height, pxwidth, pxheight))
    return false
end

function on_message(session, msg::lib.ssh_message, demo_server)::Bool
    msg_type = ssh.message_type(msg)
    msg_subtype = ssh.message_subtype(msg)
    _add_log_event!(demo_server, :message_request, (msg_type, msg_subtype))

    # Handle direct port forwarding requests
    if msg_type == ssh.RequestType_ChannelOpen && msg_subtype == lib.SSH_CHANNEL_DIRECT_TCPIP
        hostname = unsafe_string(lib.ssh_message_channel_request_open_destination(msg))
        port = lib.ssh_message_channel_request_open_destination_port(msg)

        # Set up the listener socket. Restrict ourselves to IPv4 for simplicity
        # since the test HTTP servers bind to the IPv4 loopback interface (and
        # you're not using this in production, right?).
        demo_server.fwd_socket = Sockets.connect(getaddrinfo(hostname, IPv4), port)

        # Create a task to read data from the socket and write it to the SSH channel
        demo_server.fwd_socket_task = Threads.@spawn try
            sock = demo_server.fwd_socket

            # Loop while the connection is open
            while isopen(sock)
                # Read some data
                data = readavailable(sock)

                if !isempty(data) && isopen(demo_server.fwd_sshchan)
                    # If we got something, write it to the channel
                    _add_log_event!(demo_server, :fwd_socket_data, length(data))
                    write(demo_server.fwd_sshchan, data)
                elseif isempty(data) && eof(sock)
                    # Otherwise it means the remote closed the connection and we
                    # can shutdown the port forward if it's still open.
                    close(sock)
                    if isopen(demo_server.fwd_sshchan)
                        ssh.channel_send_eof(demo_server.fwd_sshchan)
                        close(demo_server.fwd_sshchan)
                    end
                elseif eof(demo_server.fwd_sshchan)
                    # Or if the client closed the connection we also shutdown
                    # the port.
                    close(sock)
                end
            end
        catch ex
            @error "Error in port fowarding socket handler!" exception=(ex, catch_backtrace())
        end

        # Create a channel for the port forward
        channel_ptr = lib.ssh_message_channel_request_open_reply_accept(msg)
        sshchan = ssh.SshChannel(channel_ptr, session)
        ssh.set_channel_callbacks(sshchan, demo_server.fwd_channel_cb)
        demo_server.fwd_sshchan = sshchan

        return false
    end

    return true
end

function on_fwd_channel_eof(session, sshchan, demo_server)::Nothing
    _add_log_event!(demo_server, :fwd_channel_eof, true)
end

function on_fwd_channel_data(session, sshchan, data_ptr, n_bytes, is_stderr, demo_server)::Int
    _add_log_event!(demo_server, :fwd_channel_data, n_bytes)

    # When we receive data from the channel, write it to the forwarding socket
    data = unsafe_wrap(Array, Ptr{UInt8}(data_ptr), n_bytes)
    write(demo_server.fwd_socket, data)

    return n_bytes
end

function on_fwd_channel_close(session, sshchan, demo_server)::Nothing
    _add_log_event!(demo_server, :fwd_channel_close, true)
end

function on_fwd_channel_exit_status(session, sshchan, exitcode, demo_server)::Nothing
    _add_log_event!(demo_server, :fwd_channel_exit_status, exitcode)
end

function on_fwd_channel_write_wontblock(session, sshchan, n_bytes, demo_server)::Int
    _add_log_event!(demo_server, :fwd_channel_write_wontblock, n_bytes)
    return 0
end

@kwdef mutable struct DemoServer
    server::Server
    server_callbacks::ServerCallbacks = ServerCallbacks()
    channel_callbacks::ChannelCallbacks = ChannelCallbacks()
    listener_task::Union{Task, Nothing} = nothing
    sshchan::Union{ssh.SshChannel, Nothing} = nothing
    verbose::Bool = false
    password::Union{String, Nothing} = nothing

    exec_task::Union{Task, Nothing} = nothing
    exec_proc::Union{Base.Process, Nothing} = nothing

    fwd_sshchan::Union{ssh.SshChannel, Nothing} = nothing
    fwd_channel_cb::ChannelCallbacks = ChannelCallbacks()
    fwd_socket::Sockets.TCPSocket = Sockets.TCPSocket()
    fwd_socket_task::Union{Task, Nothing} = nothing

    callback_log::Dict{Symbol, Vector} = Dict{Symbol, Vector}()
    log_timeline::Vector = []
    log_lock::ReentrantLock = ReentrantLock()
    log_id::Int = 1
end

"""
$(TYPEDSIGNATURES)
"""
function DemoServer(port::Int; verbose=false, password=nothing,
                    auth_methods=[ssh.AuthMethod_None, ssh.AuthMethod_Password],
                    log_verbosity=ssh.SSH_LOG_NOLOG)
    if ssh.AuthMethod_Password in auth_methods && isnothing(password)
        throw(ArgumentError("You must pass `password` to DemoServer since password authentication is enabled"))
    end

    key = pki.generate(pki.KeyType_ed25519)
    server = ssh.Server(port; auth_methods, key, log_verbosity)

    demo_server = DemoServer(; server, verbose, password)

    ssh.set_message_callback(on_message, server, demo_server)
    demo_server.server_callbacks = ServerCallbacks(demo_server;
                                                   auth_password_function=on_auth_password,
                                                   auth_none_function=on_auth_none,
                                                   service_request_function=on_service_request,
                                                   channel_open_request_session_function=on_channel_open)
    demo_server.channel_callbacks = ChannelCallbacks(demo_server;
                                                     channel_eof_function=on_channel_eof,
                                                     channel_close_function=on_channel_close,
                                                     channel_pty_request_function=on_channel_pty_request,
                                                     channel_exec_request_function=on_channel_exec_request,
                                                     channel_env_request_function=on_channel_env_request,
                                                     channel_write_wontblock_function=on_channel_write_wontblock)

    demo_server.fwd_channel_cb = ChannelCallbacks(demo_server;
                                                  channel_eof_function=on_fwd_channel_eof,
                                                  channel_close_function=on_fwd_channel_close,
                                                  channel_data_function=on_fwd_channel_data,
                                                  channel_exit_status_function=on_fwd_channel_exit_status,
                                                  channel_write_wontblock_function=on_fwd_channel_write_wontblock)

    return demo_server
end

"""
$(TYPEDSIGNATURES)

Do-constructor to execute a function while the server is running and have it
safely cleaned up afterwards.
"""
function DemoServer(f::Function, args...; kwargs...)
    demo_server = DemoServer(args...; kwargs...)
    start(demo_server)

    try
        f()
    finally
        stop(demo_server)
    end

    return demo_server
end

function handle_session(session, ds::DemoServer)
    empty!(ds.callback_log)

    ssh.set_server_callbacks(session, ds.server_callbacks)
    if !ssh.handle_key_exchange(session)
        @error "Key exchange failed"
        return
    end

    event = ssh.SshEvent()
    ssh.event_add_session(event, session)
    while isnothing(ds.sshchan)
        ret = ssh.event_dopoll(event, session)

        if ret != ssh.SSH_OK
            break
        end
    end

    if !isnothing(ds.sshchan)
        ssh.set_channel_callbacks(ds.sshchan, ds.channel_callbacks)
        # Loop while the session is open
        while ssh.event_dopoll(event, session, ds.sshchan.close_lock) == ssh.SSH_OK
            continue
        end

        # Wait for everything that might still be using the channel
        if !isnothing(ds.exec_task)
            wait(ds.exec_task)
        end
        if !isnothing(ds.fwd_sshchan)
            close(ds.fwd_sshchan)
            close(ds.fwd_socket)
        end
        if !isnothing(ds.fwd_socket_task)
            wait(ds.fwd_socket_task)
        end

        # And then close it
        close(ds.sshchan)
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

function start(demo_server::DemoServer)
    handle_wrapper = session -> handle_session(session, demo_server)
    demo_server.listener_task = Threads.@spawn try
        ssh.listen(handle_wrapper, demo_server.server)
    catch ex
        @error "Error during listen()" exception=(ex, catch_backtrace())
    end
    ssh.wait_for_listener(demo_server.server)
end

function stop(demo_server::DemoServer)
    if !isnothing(demo_server.exec_task)
        kill(demo_server.exec_proc)
        wait(demo_server.exec_task)
    end

    if !isnothing(demo_server.listener_task)
        close(demo_server.server)
        wait(demo_server.listener_task)
        demo_server.listener_task = nothing
    end
end

function _add_log_event!(ds::DemoServer, callback_name::Symbol, event)
    @lock ds.log_lock begin
        if !haskey(ds.callback_log, callback_name)
            ds.callback_log[callback_name] = []
        end

        log_vector = ds.callback_log[callback_name]
        push!(log_vector, event)
        push!(ds.log_timeline, (callback_name, lastindex(log_vector), time()))

        if ds.verbose
            timestamp = Dates.format(Dates.now(), Dates.ISOTimeFormat)
            @info "$timestamp DemoServer: $callback_name $event"
            flush(stdout)
        end
    end
end

"""
$(TYPEDSIGNATURES)

Print a nicely formatted timeline of callbacks and their logged data.
"""
function print_timeline(ds::DemoServer)
    duration = ds.log_timeline[end][3] - ds.log_timeline[1][3]
    @printf("%d callbacks in %.3fs\n", length(ds.log_timeline), duration)

    for (id, (callback_name, log_idx, _)) in enumerate(ds.log_timeline)
        @printf("%-4d %-30s %s\n",
                id,
                callback_name,
                string(ds.callback_log[callback_name][log_idx]))
    end
end

end
