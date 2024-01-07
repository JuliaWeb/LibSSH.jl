import .Callbacks: ServerCallbacks


"""
$(TYPEDEF)
$(TYPEDFIELDS)

This object wraps a `lib.ssh_event`.
"""
mutable struct SshEvent
    ptr::Union{lib.ssh_event, Nothing}

    @doc """
    $(TYPEDSIGNATURES)

    Create an empty `SshEvent`.
    """
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

Wrapper around [`lib.ssh_event_add_session()`](@ref). The session should
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

Wrapper around [`lib.ssh_event_remove_session()`](@ref).
"""
function event_remove_session(event::SshEvent, session::Session)
    ret = lib.ssh_event_remove_session(event.ptr, session.ptr)
    if ret != SSH_OK
        throw(LibSSHException("Could not remove Session from SshEvent: $(ret)"))
    end
end

"""
$(TYPEDSIGNATURES)

Non-blocking wrapper around [`lib.ssh_event_dopoll()`](@ref), only to be used for
events that have a single session added to them (i.e. a [`SshEvent`](@ref)). All
of the channel locks passed in `sshchan_locks` will be locked while
[`lib.ssh_event_dopoll()`](@ref) executes (but will be unlocked while waiting).

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

"""
$(TYPEDSIGNATURES)

Removes the [`Session`](@ref) from the underlying `ssh_event` and frees the
event memory. This function may be safely called multiple times, and the event
will be unusable afterwards.

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
$(TYPEDEF)
$(TYPEDFIELDS)

Wrapper around [`lib.ssh_bind`](@ref).
"""
mutable struct Bind
    ptr::Union{lib.ssh_bind, Nothing}
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

    @doc """
    $(TYPEDSIGNATURES)

    Inner constructor.
    """
    function Bind(port, addr="0.0.0.0";
                  hostkey=nothing,
                  key=nothing,
                  log_verbosity=SSH_LOG_NOLOG,
                  auth_methods=[AuthMethod_Password],
                  message_callback::Union{Function, Nothing}=nothing,
                  message_callback_userdata=nothing)
        if isnothing(hostkey) && isnothing(key)
            throw(ArgumentError("Bind requires either `hostkey` or `key` to be set"))
        elseif !isnothing(hostkey) && !isnothing(key)
            throw(ArgumentError("Cannot pass both `hostkey` and `key` to Bind"))
        end

        bind_ptr = lib.ssh_bind_new()
        lib.ssh_bind_set_blocking(bind_ptr, 0)

        bind = new(bind_ptr, addr, port, hostkey, key, auth_methods, log_verbosity,
                   Base.Event(), false, ReentrantLock(),
                   nothing, nothing)
        bind.addr = addr
        bind.port = port
        if !isnothing(hostkey)
            bind.hostkey = hostkey
        end
        if !isnothing(key)
            bind.key = key
        end
        bind.auth_methods = auth_methods
        bind.log_verbosity = log_verbosity

        if !isnothing(message_callback)
            set_message_callback(message_callback, bind, message_callback_userdata)
        end

        finalizer(bind) do bind
            close(bind)

            # When a SshKey (lib.ssh_key) is added to a lib.ssh_bind,
            # lib.ssh_bind_free() will automatically free the key. This means
            # that when the SshKey finalizer is executed it will attempt to do a
            # double-free, causing a segfault. We get around that by manually
            # setting SshKey.ptr to nothing to tell its finalizer the memory has
            # already been free'd.
            if !isnothing(bind.key)
                bind.key.ptr = nothing
            end
        end
    end
end

"""
$(TYPEDSIGNATURES)

Close and free the bind.
"""
function Base.close(bind::Bind)
    if isopen(bind)
        lib.ssh_bind_free(bind.ptr)
        bind.ptr = nothing
    end
end

"""
$(TYPEDSIGNATURES)

Lock a bind for thread-safe operations.
"""
Base.lock(bind::Bind) = lock(bind._lock)

"""
$(TYPEDSIGNATURES)

Unlock a bind.
"""
Base.unlock(bind::Bind) = unlock(bind._lock)

"""
$(TYPEDSIGNATURES)

Check if the bind has been free'd yet.
"""
Base.isopen(bind::Bind) = !isnothing(bind.ptr)

"""
$(TYPEDSIGNATURES)

Get the last error set by libssh. Wrapper around [`lib.ssh_get_error()`](@ref).
"""
function get_error(bind::Bind)
    if isnothing(bind.ptr)
        throw(ArgumentError("Bind data has been free'd, cannot get its error"))
    end

    ret = lib.ssh_get_error(Ptr{Cvoid}(bind.ptr))
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

function Base.setproperty!(bind::Bind, name::Symbol, value)
    @lock bind begin
        if name ∉ fieldnames(Bind)
            error("type Bind has no field $(name)")
        end

        ret = -1

        if name ∉ keys(BIND_PROPERTY_OPTIONS)
            return setfield!(bind, name, value)
        else
            # We don't allow 'unsetting' options, that would be too complicated to implement
            if isnothing(value)
                throw(ArgumentError("Setting Bind options to nothing is unsupported"))
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

                ret = lib.ssh_bind_options_set(bind.ptr, option, cvalue)
            end
        end

        if ret != 0
            throw(LibSSHException("Error setting Bind.$(name) to $(value): $(ret)"))
        end

        # Get the type of the field in the struct. Some of them are unions, in which
        # case we select the first non-Nothing type in the Union. If the saved type
        # doesn't match the type of the passed value, we convert it.
        final_value = value
        saved_type = fieldtype(Bind, name)
        if saved_type isa Union
            possible_types = filter(!=(Nothing), union_types(saved_type))
            saved_type = possible_types[1]
        end
        if !(value isa saved_type)
            final_value = saved_type(value)
        end

        return setfield!(bind, name, final_value)
    end
end

# Wrapper around the user-defined message callback
function _message_callback_wrapper(session_ptr::lib.ssh_session, message::lib.ssh_message, bind_ptr::Ptr{Cvoid})::Cint
    bind::Bind = unsafe_pointer_to_objref(bind_ptr)
    session = Session(session_ptr; own=false)

    jl_result::Bool = true
    try
        jl_result = bind._message_callback(session, message, bind._message_callback_userdata)
    catch ex
        @error "Exception in message_callback!" exception=(ex, catch_backtrace())
    end

    return Cint(jl_result)
end

"""
$(TYPEDSIGNATURES)

High-level function to listen for incoming requests and pass them off to a
handler function. This will already set the auth methods on the session (from
`Bind.auth_methods`) before calling the handler.

The `poll_timeout` argument refers to the timeout for polling the bind
socket for new connections. It must be >0 because otherwise it would never wake
up if the socket was closed while waiting, but other than that the exact value
doesn't matter much. It'll only control how frequently the listen loop wakes up
to check if the bind has been closed yet.
"""
function listen(handler::Function, bind::Bind; poll_timeout=0.1)
    if poll_timeout < 0
        throw(ArgumentError("poll_timeout cannot be negative!"))
    end

    ret = lib.ssh_bind_listen(bind.ptr)
    if ret != SSH_OK
        # If binding fails, we wake up any waiting tasks and throw an exception
        notify(bind._listener_event)
        throw(LibSSHException("Error on LibSSH.lib.ssh_bind_listen(): $(get_error(bind))"))
    end

    message_callback_cfunc = @cfunction(_message_callback_wrapper,
                                        Cint,
                                        (lib.ssh_session, lib.ssh_message, Ptr{Cvoid}))

    fd = RawFD(lib.ssh_bind_get_fd(bind.ptr))
    while isopen(bind)
        # Notify listeners that we've started
        if !bind._listener_started
            bind._listener_started = true
            notify(bind._listener_event)
        end

        # Wait for new connection attempts. Note that there's a race condition
        # between the loop condition evaluation and this line, so we wrap
        # poll_fd() in a try-catch in case the bind (and thus the file
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

        # The first thing we do is check if the Bind has been closed, because
        # that means that the file descriptor was closed while we were polling
        # it, potentially by another thread. That matters because according to
        # the close(2) docs it's unsafe to close file descriptors while they're
        # being polled in another thread because they may be reused, which could
        # lead to race conditions. Hence, we first check that the Bind hasn't
        # been closed to make sure that we didn't get a wakeup from some new
        # resource using the old file descriptor.
        if !isopen(bind)
            break
        elseif poll_result.timedout
            continue
        end

        # Accept the new connection
        session_ptr = lib.ssh_new()
        ret = lib.ssh_bind_accept(bind.ptr, session_ptr)
        if ret != SSH_OK
            throw(LibSSHException("Error when accepting new connection: $(ret)"))
        end

        session = Session(session_ptr)

        # Set the auth methods supported by the bind
        set_auth_methods(session, bind.auth_methods)

        # Set the message callback, if there is one
        if !isnothing(bind._message_callback)
            lib.ssh_set_message_callback(session_ptr, message_callback_cfunc, pointer_from_objref(bind))
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

Waits for the main loop of [`listen`](@ref) to begin running on the bind.
"""
function wait_for_listener(bind::Bind)
    wait(bind._listener_event)
end

"""
$(TYPEDSIGNATURES)

Set authentication methods on a [`Session`](@ref).

Wrapper around [`lib.ssh_set_auth_methods()`](@ref).
"""
function set_auth_methods(session::Session, auth_methods::Vector{AuthMethod})
    bitflag = reduce(|, Int.(auth_methods))
    lib.ssh_set_auth_methods(session.ptr, bitflag)
end

"""
$(TYPEDSIGNATURES)

Set authentication methods for a `lib.ssh_message`.

Wrapper around [`lib.message_auth_set_methods()`](@ref).
"""
function set_auth_methods(msg::lib.ssh_message, auth_methods::Vector{AuthMethod})
    bitflag = reduce(|, Int.(auth_methods))
    lib.message_auth_set_methods(msg, bitflag)
end

"""
$(TYPEDSIGNATURES)

Non-blocking wrapper around [`lib.ssh_handle_key_exchange()`](@ref). Returns
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

Set callbacks for a Session. Wrapper around [`lib.ssh_set_server_callbacks()`](@ref).
"""
function set_server_callbacks(session::Session, callbacks::ServerCallbacks)
    ret = lib.ssh_set_server_callbacks(session.ptr, Ref(callbacks.cb_struct::lib.ssh_server_callbacks_struct))
    if ret != SSH_OK
        throw(LibSSHException("Error setting server callbacks: $(ret)"))
    end
end

"""
$(TYPEDSIGNATURES)

Set message callbacks for the sessions accepted by a Bind. This must be set
before [`listen`](@ref) is called to take effect. [`listen`](@ref) will
automatically set the callback before passing the session to the user handler.

The callback function must have the signature:

    f(session::Session, msg::lib.ssh_message, userdata)::Bool

The return value indicates whether further handling of the message is necessary.
It should be `true` if the message wasn't handled or needs to be handled by
libssh, or `false` if the message was completely handled and doesn't need any
more action from libssh.
"""
function set_message_callback(f::Function, bind::Bind, userdata)
    if !hasmethod(f, (Session, lib.ssh_message, typeof(userdata)))
        throw(ArgumentError("Callback function f() doesn't have the right signature"))
    end

    bind._message_callback = f
    bind._message_callback_userdata = userdata

    return nothing
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
import ..Bind
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
    demo_server.authenticated = password == demo_server.password

    return demo_server.authenticated ? ssh.AuthStatus_Success : ssh.AuthStatus_Denied
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

    # Handle keyboard-interactive authentication
    if msg_type == ssh.RequestType_Auth && msg_subtype == lib.SSH_AUTH_METHOD_INTERACTIVE
        if demo_server.authenticated
            _add_log_event!(demo_server, :auth_kbdint, "already authenticated")
            lib.message_auth_reply_success(msg, Int(false))
            return false
        end

        if !lib.message_auth_kbdint_is_response(msg)
            # This means the user is requesting authentication
            user = lib.message_auth_user(msg)
            _add_log_event!(demo_server, :auth_kbdint, user)
            ssh.message_auth_interactive_request(msg, "Demo server login", "Enter your details.",
                                                 ["Password: ", "Token: "], [true, true])
            return false
        else
            # Now they're responding to our prompts
            n_answers = lib.ssh_userauth_kbdint_getnanswers(session.ptr)

            # If they didn't return the correct number of answers, deny the request
            if n_answers != 2
                _add_log_event!(demo_server, :auth_kbdint, "denied")
                lib.message_reply_default(msg)
                return false
            end

            # Get the answers and check them
            password = lib.userauth_kbdint_getanswer(session.ptr, 0)
            token = lib.userauth_kbdint_getanswer(session.ptr, 1)
            if password == "foo" && token == "bar"
                _add_log_event!(demo_server, :auth_kbdint, "accepted with '$password' and '$token'")
                lib.message_auth_reply_success(msg, Int(false))
                demo_server.authenticated = true
                return false
            end

            return true
        end
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

"""
$(TYPEDEF)

Fields:
$(TYPEDFIELDS)

The `DemoServer` is an extremely simple and limited implementation of an SSH
server using the libssh server API. It's so limited in fact that for the sake of
simplicity it only supports a single 'operation' per instance after
authentication (e.g. running one command or forwarding one port). It's sole
reason for existence is to be used in test suites to test client code. Do
**not** expose this publicly! See the constructors docstrings for examples of
how to use it (the LibSSH.jl test suite may also be informative).

Supported features:
- Password authentication: only the password is checked, not the username.
- Keyboard-interactive authentication: the server will give two prompts for a
  `Password:` and `Token:` and expect `foo` and `bar` as answers, respectively.
- Command execution: note that requested environment variables from the client
  are currently ignored, and the command output will only be sent back to the
  client after the command has finished.
- Direct port forwarding

Unsupported features (that may be implemented in the future):
- Public key authentication
- GSSAPI authentication
- Reverse port forwarding
"""
@kwdef mutable struct DemoServer
    bind::Bind
    server_callbacks::ServerCallbacks = ServerCallbacks()
    channel_callbacks::ChannelCallbacks = ChannelCallbacks()
    listener_task::Union{Task, Nothing} = nothing
    sshchan::Union{ssh.SshChannel, Nothing} = nothing
    verbose::Bool = false
    password::Union{String, Nothing} = nothing
    authenticated::Bool = false

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

Creates a [`DemoServer`](@ref).

## Parameters

- `port`: The port to listen to.
- `verbose`: This verbosity doesn't refer to the log messages from libssh but
  from the `DemoServer`. If this is `true` it print messages on events like
  authentication etc. Useful for high-level debugging. The events can always be
  printed afterwards with [`Demo.print_timeline`](@ref).
- `password`: The password to use if password authentication is enabled.
- `auth_methods`: A list of authentication methods to enable. See
  [`ssh.AuthMethod`](@ref).
- `log_verbosity`: Controls the logging of libssh itself. This could be
  e.g. `lib.SSH_LOG_WARNING` (see the [upstream
  documentation](https://api.libssh.org/stable/group__libssh__log.html#ga06fc87d81c62e9abb8790b6e5713c55b)).
"""
function DemoServer(port::Int; verbose::Bool=false, password::Union{String, Nothing}=nothing,
                    auth_methods=[ssh.AuthMethod_None, ssh.AuthMethod_Password],
                    log_verbosity=ssh.SSH_LOG_NOLOG)
    if ssh.AuthMethod_Password in auth_methods && isnothing(password)
        throw(ArgumentError("You must pass `password` to DemoServer since password authentication is enabled"))
    end

    key = pki.generate(pki.KeyType_ed25519)
    bind = ssh.Bind(port; auth_methods, key, log_verbosity)

    demo_server = DemoServer(; bind, verbose, password)

    ssh.set_message_callback(on_message, bind, demo_server)
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

Do-constructor to execute a function `f()` while the server is running and have
it safely cleaned up afterwards. There are two keyword arguments to be aware of:
- `timeout` (default 10s): set a timeout in seconds for `f()`. If `f()` doesn't finish before
  the timeout an `InterruptException` will be thrown to it.
- `kill_timeout` (default 3s): set a waiting time in seconds for `f()` to exit *after*
  throwing it an `InterruptException`. Sometimes you may want to cleanup things
  before exiting, and this gives some time to do that. If `f()` isn't finished
  after `kill_timeout` no futher action will be taken.

`args` and `kwargs` will all be passed to [`DemoServer(::Int)`](@ref).

## Examples

```julia-repl
julia> import LibSSH.Demo: DemoServer

julia> DemoServer(2222; password="foo") do
           run(`sshpass -p foo ssh -o NoHostAuthenticationForLocalhost=yes -p 2222 localhost echo 'Hello world!'`)
       end
Hello world!
```
"""
function DemoServer(f::Function, args...; timeout=10, kill_timeout=3, kwargs...)
    demo_server = DemoServer(args...; kwargs...)
    start(demo_server)

    timer = Timer(timeout)
    still_running = true
    t = Threads.@spawn try
        f()
    finally
        still_running = false
        close(timer)
    end

    # Wait for a timeout or the function to finish
    try
        wait(timer)
    catch
        # An exception means that the function finished in time and closed
        # the timer early.
    end

    # If the function is still running, we attempt to kill it explicitly
    kill_failed = nothing
    if still_running
        @async Base.throwto(t, InterruptException())
        result = timedwait(() -> istaskdone(t), kill_timeout)
        kill_failed = result == :timed_out
    end

    # After attempting to kill the function we stop the server
    stop(demo_server)

    # If there was a timeout we throw an exception, otherwise we wait() on
    # the task, which will cause any exeption thrown by f() to bubble up.
    if !isnothing(kill_failed)
        kill_failed_msg = kill_failed ? " (failed to kill function after $(kill_timeout)s, it's still running)" : ""
        error("DemoServer function timed out after $(timeout)s" * kill_failed_msg)
    else
        wait(t)
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

"""
$(TYPEDSIGNATURES)

Start a [`DemoServer`](@ref), which means bind to a port and start the
[`ssh.listen`](@ref) loop.
"""
function start(demo_server::DemoServer)
    handle_wrapper = session -> handle_session(session, demo_server)
    demo_server.listener_task = Threads.@spawn try
        ssh.listen(handle_wrapper, demo_server.bind)
    catch ex
        @error "Error during listen()" exception=(ex, catch_backtrace())
    end
    ssh.wait_for_listener(demo_server.bind)
end

"""
$(TYPEDSIGNATURES)

Stop a [`DemoServer`](@ref).
"""
function stop(demo_server::DemoServer)
    if !isnothing(demo_server.exec_task)
        kill(demo_server.exec_proc)
        wait(demo_server.exec_task)
    end

    if !isnothing(demo_server.listener_task)
        close(demo_server.bind)
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

Print a nicely formatted timeline of callbacks and their logged data. Useful
when debugging.
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
