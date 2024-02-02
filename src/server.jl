import .Callbacks: ServerCallbacks


"""
$(TYPEDEF)
$(TYPEDFIELDS)

This object wraps a `lib.ssh_event`, but it's designed to only allow adding a
single session to it. Use this in a server to poll the session.
"""
mutable struct SessionEvent
    ptr::Union{lib.ssh_event, Nothing}
    session::Session

    @doc """
    $(TYPEDSIGNATURES)

    Create an empty `SessionEvent`.
    """
    function SessionEvent(session::Session)
        ptr = lib.ssh_event_new()
        if ptr == C_NULL
            throw(LibSSHException("Could not allocate ssh_event"))
        end

        ret = lib.ssh_event_add_session(ptr, session.ptr)
        if ret != SSH_OK
            lib.ssh_event_free(ptr)
            throw(LibSSHException("Could not add Session to SessionEvent: $(ret)"))
        end

        self = new(ptr, session)
        finalizer(close, self)
    end
end

function _finalizer(event::SessionEvent)
    try
        close(event)
    catch ex
        Threads.@spawn @error "Exception when finalizing SessionEvent" exception=(ex, catch_backtrace())
    end
end

"""
$(TYPEDSIGNATURES)

Non-blocking wrapper around [`lib.ssh_event_dopoll()`](@ref). This may trigger
callbacks on the session and its channels.

Returns either `SSH_OK` or `SSH_ERROR`.
"""
function event_dopoll(event::SessionEvent)
    ret = _session_trywait(event.session) do
        # Lock the channels while polling, otherwise close(::SshChannel) may be
        # called in the meantime by the callbacks, which can cause segfaults. We
        # store the locked channels in an array so we can unlock only these
        # channels after polling. This is necessary in case a channel is added
        # during the poll, trying to unlock an unlocked channel will cause an
        # error.
        locked_channels = SshChannel[]
        for sshchan in event.session.channels
            lock(sshchan.close_lock)
            push!(locked_channels, sshchan)
        end

        # Always check if the event is still assigned within the loop since it
        # may be closed at any time.
        ret = if isassigned(event)
            lib.ssh_event_dopoll(event.ptr, 0)
        else
            SSH_ERROR
        end

        for sshchan in locked_channels
            unlock(sshchan.close_lock)
        end

        return ret
    end

    return ret
end

"""
$(TYPEDSIGNATURES)

Removes the [`Session`](@ref) from the underlying `ssh_event` and frees the
event memory. This function may be safely called multiple times, and the event
will be unusable afterwards.
"""
function Base.close(event::SessionEvent)
    # Developer note: this function is called by the finalizer so we can't do
    # any task switches, including print statements.

    if isassigned(event)
        # Attempt to remove the session. Note that we don't bother checking the
        # return code because some other callback may have already removed the
        # session, which will cause this to return SSH_ERROR.
        if isassigned(event.session)
            lib.ssh_event_remove_session(event.ptr, event.session.ptr)
        end

        # Free the ssh_event
        lib.ssh_event_free(event.ptr)
        event.ptr = nothing
    end
end

"""
$(TYPEDSIGNATURES)

Check if a `SessionEvent` holds a valid pointer to a `lib.ssh_event`.
"""
Base.isassigned(event::SessionEvent) = !isnothing(event.ptr)

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

function Base.show(io::IO, bind::Bind)
    print(io, Bind, "(addr=$(bind.addr), port=$(bind.port))")
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
    session.server_callbacks = callbacks
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


function on_auth_password(session, user, password, client)::ssh.AuthStatus
    _add_log_event!(client, :auth_password, (user, password))
    client.authenticated = password == client.password

    return client.authenticated ? ssh.AuthStatus_Success : ssh.AuthStatus_Denied
end

function on_auth_none(session, user, client)::ssh.AuthStatus
    _add_log_event!(client, :auth_none, true)
    return ssh.AuthStatus_Denied
end

function on_service_request(session, service, client)::Bool
    _add_log_event!(client, :service_request, service)
    return true
end

function on_channel_open(session, client)::Union{ssh.SshChannel, Nothing}
    _add_log_event!(client, :channel_open, true)
    sshchan = ssh.SshChannel(client.session)
    ssh.set_channel_callbacks(sshchan, client.channel_callbacks)
    push!(client.unclaimed_channels, sshchan)

    return sshchan
end

function on_channel_env_request(session, sshchan, name, value, client)::Bool
    _add_log_event!(client, :channel_env_request, (name, value))
    return true
end

function on_channel_exec_request(session, sshchan, command, client)::Bool
    _add_log_event!(client, :channel_exec_request, command)

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
    idx = findfirst(x -> x.ptr == sshchan.ptr, client.unclaimed_channels)
    if isnothing(idx)
        @error "Couldn't find the requested SshChannel in the client"
        return false
    end

    owning_sshchan = popat!(client.unclaimed_channels, idx)
    push!(client.channel_operations, CommandExecutor(command, owning_sshchan))

    return true
end

function on_channel_eof(session, sshchan, client)::Nothing
    _add_log_event!(client, :channel_eof, true)
    return nothing
end

function on_channel_close(session, sshchan, client)::Nothing
    _add_log_event!(client, :channel_close, true)

    all_channels = copy(client.unclaimed_channels)
    for op in client.channel_operations
        append!(all_channels, getchannels(op))
    end

    # It's ok if we don't find a matching channel, that just means that we've
    # already closed it from our side.
    idx = findfirst(x -> x.ptr == sshchan.ptr, all_channels)
    if !isnothing(idx)
        close(all_channels[idx])
    end
end

function on_channel_pty_request(session, sshchan, term, width, height, pxwidth, pxheight, client)::Bool
    _add_log_event!(client, :channel_pty_request, (term, width, height, pxwidth, pxheight))
    return false
end

function on_message(session, msg::lib.ssh_message, demo_server)::Bool
    # Find the client to which the session belongs
    idx = findfirst(client -> client.session.ptr == session.ptr, demo_server.clients)
    if isnothing(idx)
        @warn "Couldn't find a client for session $(session.ptr)"
        return true
    end
    client = demo_server.clients[idx]

    msg_type = ssh.message_type(msg)
    msg_subtype = ssh.message_subtype(msg)
    _add_log_event!(client, :message_request, (msg_type, msg_subtype))

    # Handle direct port forwarding requests
    if msg_type == ssh.RequestType_ChannelOpen && msg_subtype == lib.SSH_CHANNEL_DIRECT_TCPIP
        hostname = unsafe_string(lib.ssh_message_channel_request_open_destination(msg))
        port = lib.ssh_message_channel_request_open_destination_port(msg)

        # Create a channel for the port forward
        channel_ptr = lib.ssh_message_channel_request_open_reply_accept(msg)
        sshchan = ssh.SshChannel(channel_ptr, client.session)
        push!(client.channel_operations, Forwarder(client, sshchan, hostname, port))

        return false
    end

    # Handle keyboard-interactive authentication
    if msg_type == ssh.RequestType_Auth && msg_subtype == lib.SSH_AUTH_METHOD_INTERACTIVE
        if client.authenticated
            _add_log_event!(client, :auth_kbdint, "already authenticated")
            lib.message_auth_reply_success(msg, Int(false))
            return false
        end

        if !lib.message_auth_kbdint_is_response(msg)
            # This means the user is requesting authentication
            user = lib.message_auth_user(msg)
            _add_log_event!(client, :auth_kbdint, user)
            ssh.message_auth_interactive_request(msg, "Demo server login", "Enter your details.",
                                                 ["Password: ", "Token: "], [true, true])
            return false
        else
            # Now they're responding to our prompts
            n_answers = lib.ssh_userauth_kbdint_getnanswers(session.ptr)

            # If they didn't return the correct number of answers, deny the request
            if n_answers != 2
                _add_log_event!(client, :auth_kbdint, "denied")
                lib.message_reply_default(msg)
                return false
            end

            # Get the answers and check them
            password = lib.userauth_kbdint_getanswer(session.ptr, 0)
            token = lib.userauth_kbdint_getanswer(session.ptr, 1)
            if password == "foo" && token == "bar"
                _add_log_event!(client, :auth_kbdint, "accepted with '$password' and '$token'")
                lib.message_auth_reply_success(msg, Int(false))
                client.authenticated = true
                return false
            end

            return true
        end
    end

    return true
end

@kwdef mutable struct Client
    id::Int
    session::ssh.Session
    verbose::Bool
    password::Union{String, Nothing}
    authenticated::Bool = false

    session_event::Union{ssh.SessionEvent, Nothing} = nothing
    channel_callbacks::ChannelCallbacks = ChannelCallbacks()
    unclaimed_channels::Vector{ssh.SshChannel} = ssh.SshChannel[]
    channel_operations::Vector{Any} = []

    task::Union{Task, Nothing} = nothing
    log_timeline::Vector = []
    log_lock::ReentrantLock = ReentrantLock()
    log_id::Int = 1
    callback_log::Dict{Symbol, Vector} = Dict{Symbol, Vector}()
end

function Base.close(client::Client)
    for op in client.channel_operations
        close(op)
    end

    close(client.session_event)
    wait(client.task)
end

"""
$(TYPEDEF)
$(TYPEDFIELDS)
"""
@kwdef mutable struct DemoServer
    bind::Bind
    listener_task::Union{Task, Nothing} = nothing
    sshchan::Union{ssh.SshChannel, Nothing} = nothing
    verbose::Bool = false
    password::Union{String, Nothing} = nothing

    clients::Vector{Client} = Client[]
end

function Base.show(io::IO, ds::DemoServer)
    print(io, DemoServer, "(bind.port=$(ds.bind.port))")
end

"""
$(TYPEDSIGNATURES)

Creates a [`DemoServer`](@ref).

# Arguments

- `port`: The port to listen to.
- `verbose=false`: This verbosity doesn't refer to the log messages from libssh but
  from the `DemoServer`. If this is `true` it print messages on events like
  authentication etc. Useful for high-level debugging. The events can always be
  printed afterwards with [`Demo.print_timeline`](@ref).
- `password=nothing`: The password to use if password authentication is enabled.
- `auth_methods=[AuthMethod_None, AuthMethod_Password]`: A list of
  authentication methods to enable. See [`ssh.AuthMethod`](@ref).
- `log_verbosity=nothing`: Controls the logging of libssh itself. This could be
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

# Examples

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
        kill_failed_msg = (kill_failed && !istaskdone(t)) ? " (failed to kill function after $(kill_timeout)s, it's still running)" : ""
        error("DemoServer function timed out after $(timeout)s" * kill_failed_msg)
    else
        wait(t)
    end

    return demo_server
end

function _handle_client(session::ssh.Session, ds::DemoServer)
    client = Client(; id=length(ds.clients) + 1,
                     session,
                     password=ds.password,
                     verbose=ds.verbose)
    server_callbacks = ServerCallbacks(client;
                                       on_auth_password=on_auth_password,
                                       on_auth_none=on_auth_none,
                                       on_service_request=on_service_request,
                                       on_channel_open_request_session=on_channel_open)
    client.channel_callbacks = ChannelCallbacks(client;
                                                on_eof=on_channel_eof,
                                                on_close=on_channel_close,
                                                on_pty_request=on_channel_pty_request,
                                                on_exec_request=on_channel_exec_request,
                                                on_env_request=on_channel_env_request)
    client.task = current_task()

    ssh.set_server_callbacks(session, server_callbacks)
    if !ssh.handle_key_exchange(session)
        @error "Key exchange failed"
        return
    end

    push!(ds.clients, client)

    client.session_event = ssh.SessionEvent(session)
    while true
        ret = ssh.event_dopoll(client.session_event)
        if ret != ssh.SSH_OK
            break
        end
    end

    close(client.session_event)
end

"""
$(TYPEDSIGNATURES)

Start a [`DemoServer`](@ref), which means bind to a port and start the
[`ssh.listen`](@ref) loop.
"""
function start(demo_server::DemoServer)
    demo_server.listener_task = Threads.@spawn try
        ssh.listen(session -> _handle_client(session, demo_server), demo_server.bind)
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
    for client in demo_server.clients
        close(client)
    end

    if !isnothing(demo_server.listener_task)
        close(demo_server.bind)
        wait(demo_server.listener_task)
        demo_server.listener_task = nothing
    end
end

function _add_log_event!(client::Client, callback_name::Symbol, event)
    @lock client.log_lock begin
        if !haskey(client.callback_log, callback_name)
            client.callback_log[callback_name] = []
        end

        log_vector = client.callback_log[callback_name]
        push!(log_vector, event)
        push!(client.log_timeline, (callback_name, lastindex(log_vector), time()))

        if client.verbose
            timestamp = Dates.format(Dates.now(), Dates.ISOTimeFormat)
            @info "$timestamp DemoServer client $(client.id): $callback_name $event"
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

## Execute commands

function exec_command(executor)
    sshchan = executor.sshchan
    cmd_stdout = IOBuffer()
    cmd_stderr = IOBuffer()

    # Start the process and wait for it
    proc = run(pipeline(ignorestatus(`sh -c $(executor.command)`); stdout=cmd_stdout, stderr=cmd_stderr);
               wait=false)
    executor.process = proc
    notify(executor._started_event)
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

@kwdef mutable struct CommandExecutor
    command::String
    sshchan::ssh.SshChannel
    task::Union{Task, Nothing} = nothing
    process::Union{Base.Process, Nothing} = nothing

    _started_event::Base.Event = Base.Event()
end

function CommandExecutor(command::String, sshchan::ssh.SshChannel)
    if !sshchan.owning
        throw(ArgumentError("The passed SshChannel is non-owning, CommandExecutor requires an owning SshChannel"))
    end

    executor = CommandExecutor(; command, sshchan)

    executor.task = Threads.@spawn try
        exec_command(executor)
    catch ex
        @error "Error when running command" exception=(ex, catch_backtrace())
    end

    return executor
end

function Base.close(executor::CommandExecutor)
    wait(executor._started_event)
    kill(executor.process)
    wait(executor.task)
end

getchannels(executor::CommandExecutor) = [executor.sshchan]

# Direct port forwarding

function on_fwd_channel_eof(session, sshchan, forwarder)::Nothing
    _add_log_event!(forwarder.client, :fwd_channel_eof, true)
end

function on_fwd_channel_data(session, sshchan, data, is_stderr, forwarder)::Int
    _add_log_event!(forwarder.client, :fwd_channel_data, length(data))

    # When we receive data from the channel, write it to the forwarding socket
    write(forwarder.socket, data)

    return length(data)
end

function on_fwd_channel_close(session, sshchan, forwarder)::Nothing
    _add_log_event!(forwarder.client, :fwd_channel_close, true)
end

function on_fwd_channel_exit_status(session, sshchan, exitcode, forwarder)::Nothing
    _add_log_event!(forwarder.client, :fwd_channel_exit_status, exitcode)
end

@kwdef mutable struct Forwarder
    client::Client
    sshchan::ssh.SshChannel
    socket::Sockets.TCPSocket = Sockets.TCPSocket()
    task::Union{Task, Nothing} = nothing
end

function Forwarder(client::Client, sshchan::ssh.SshChannel, hostname::String, port::Integer)
    self = Forwarder(; client, sshchan)
    channel_callbacks = ChannelCallbacks(self;
                                         on_eof=on_fwd_channel_eof,
                                         on_close=on_fwd_channel_close,
                                         on_data=on_fwd_channel_data,
                                         on_exit_status=on_fwd_channel_exit_status)
    ssh.set_channel_callbacks(sshchan, channel_callbacks)

    # Set up the listener socket. Restrict ourselves to IPv4 for simplicity
    # since the test HTTP servers bind to the IPv4 loopback interface (and
    # you're not using this in production, right?).
    self.socket = Sockets.connect(getaddrinfo(hostname, IPv4), port)
    self.task = Threads.@spawn try
        _forward_socket_data(self)
    catch ex
        @error "Error in port fowarding socket handler!" exception=(ex, catch_backtrace())
    end

    return self
end

getchannels(forwarder::Forwarder) = [forwarder.sshchan]

function Base.close(forwarder::Forwarder)
    close(forwarder.socket)
    wait(forwarder.task)
end

function _forward_socket_data(forwarder::Forwarder)
    sock = forwarder.socket

    # Loop while the connection is open
    while isopen(sock)
        # Read some data
        data = readavailable(sock)

        if !isempty(data) && isopen(forwarder.sshchan)
            # If we got something, write it to the channel
            _add_log_event!(forwarder.client, :fwd_socket_data, length(data))
            write(forwarder.sshchan, data)
        elseif isempty(data) && eof(sock)
            # Otherwise it means the remote closed the connection and we
            # can shutdown the port forward if it's still open.
            close(sock)
            if isopen(forwarder.sshchan)
                ssh.channel_send_eof(forwarder.sshchan)
                close(forwarder.sshchan)
            end
        elseif eof(forwarder.sshchan)
            # Or if the client closed the connection we also shutdown
            # the port.
            close(sock)
        end
    end
end

end
