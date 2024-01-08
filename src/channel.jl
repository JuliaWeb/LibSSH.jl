import Dates

import Sockets
import Sockets: TCPServer, TCPSocket, IPv4, getaddrinfo

"""
$(TYPEDEF)
$(TYPEDFIELDS)

Wraps a `lib.ssh_channel`. An `SshChannel` can be owning or non-owning
of a pointer to the underlying `lib.ssh_channel`, and only owning `SshChannel`s
can be closed with [`close(::SshChannel)`](@ref).

The type is named `SshChannel` to avoid confusion with Julia's own `Channel`
type.
"""
mutable struct SshChannel
    ptr::Union{lib.ssh_channel, Nothing}
    owning::Bool
    session::Union{Session, Nothing}
    close_lock::ReentrantLock
    local_eof::Bool

    @doc """
    $(TYPEDSIGNATURES)

    Wrap a `SshChannel` around an already existing `lib.ssh_channel`. Don't use
    this unless you know what you're doing, prefer the
    [`SshChannel(::Session)`](@ref) constructor instead.
    """
    function SshChannel(ptr::lib.ssh_channel, session=nothing; own=true)
        if own && isnothing(session)
            throw(ArgumentError("You must pass a session to an owning SshChannel"))
        elseif !own && !isnothing(session)
            throw(ArgumentError("Only owning SshChannels can be associated with a Session"))
        end
        self = new(ptr, own, session, ReentrantLock(), false)

        if own
            push!(session.channels, self)
            finalizer(_finalizer, self)
        end

        return self
    end
end

# close(SshChannel) can throw, which we don't want to happen in a finalizer so
# we wrap it in a try-catch.
function _finalizer(sshchan::SshChannel)
    try
        close(sshchan)
    catch ex
        # Note the use of @async to avoid a task switch, which is forbidden in a
        # finalizer.
        Threads.@spawn @error "Caught exception while finalizing SshChannel" exception=(ex, catch_backtrace())
    end
end

"""
$(TYPEDSIGNATURES)

Create a channel from an existing session. Note that creating the channel will
fail unless the session is connected *and* authenticated.
"""
function SshChannel(session::Session)
    if !isconnected(session)
        throw(ArgumentError("Cannot create a SshChannel on an unconnected Session"))
    end

    ptr = lib.ssh_channel_new(session.ptr)
    if ptr == C_NULL
        throw(LibSSHException("Could not allocate ssh_channel (hint: check that the session is authenticated)"))
    end

    return SshChannel(ptr, session)
end

"""
$(TYPEDSIGNATURES)

Do-constructor for a `SshChannel`. This will ensure that the channel is closed
after `f()` completes.

Example:
```julia
data = ssh.SshChannel(session) do sshchan
    return 42
end
@assert data == 42
```
"""
function SshChannel(f::Function, session::Session)
    sshchan = SshChannel(session)

    try
        return f(sshchan)
    finally
        close(sshchan)
    end
end

"""
$(TYPEDSIGNATURES)

Check if the channel holds a valid pointer to a `lib.ssh_channel`.
"""
function Base.isassigned(sshchan::SshChannel)
    !isnothing(sshchan.ptr)
end

"""
$(TYPEDSIGNATURES)

Checks if the channel is open. Wrapper around
[`lib.ssh_channel_is_open()`](@ref).
"""
function Base.isopen(sshchan::SshChannel)
    if isassigned(sshchan)
        lib.ssh_channel_is_open(sshchan.ptr) != 0
    else
        false
    end
end

"""
$(TYPEDSIGNATURES)

Closes the channel, and then frees its memory. To avoid the risk of
double-frees, this function may only be called on *owning* `SshChannel`s. It
will hold the `close_lock` of the channel during execution.
"""
function Base.close(sshchan::SshChannel)
    # Developer note: this function is called by the SshChannel finalizer, which
    # means we aren't allowed to do task switches.

    if !sshchan.owning
        throw(ArgumentError("Calling close() on a non-owning SshChannel is not allowed to avoid accidental double-frees, see the docs for more information."))
    end

    # Even though we hold a lock in this section it's still possible for the
    # function to be called recursively and enter it again anyway. The reason is
    # because lib.ssh_channel_send_eof() and lib.ssh_channel_close() both flush
    # the channel, which will trigger any callbacks. And if the callbacks happen
    # to call close(), then the lock will be taken anyway (because it's a
    # reentrant lock). There's not much we can do about this apart from making
    # close() as robust as possible, which is why there are so many checks.
    @lock sshchan.close_lock begin
        if isassigned(sshchan)
            # Remove from the sessions list of active channels. findfirst()
            # should only return nothing if the function is being called
            # recursively (i.e. through a callback) and it was already removed.
            idx = findfirst(x -> x === sshchan, sshchan.session.channels)
            if !isnothing(idx)
                popat!(sshchan.session.channels, idx)
            end

            # Close the channel
            if isopen(sshchan)
                # This will trigger callbacks
                channel_send_eof(sshchan)

                if isopen(sshchan)
                    # This will trigger callbacks
                    ret = lib.ssh_channel_close(sshchan.ptr)
                    if ret != SSH_OK
                        throw(LibSSHException("Closing SshChannel failed: $(ret)"))
                    end
                end
            end

            # Free the memory
            if isassigned(sshchan)
                lib.ssh_channel_free(sshchan.ptr)
                sshchan.ptr = nothing
            end
        end
    end
end

"""
$(TYPEDSIGNATURES)

Write a string to the channel and return the number of code units written.

Wrapper around
[`lib.ssh_channel_write()`](@ref)/[`lib.ssh_channel_write_stderr()`](@ref).
"""
function Base.write(sshchan::SshChannel, data::AbstractString; stderr::Bool=false)
    array = Vector{UInt8}(data)
    return write(sshchan, array; stderr)
end

"""
$(TYPEDSIGNATURES)

Write a byte array to the channel and return the number of bytes written (should
always match the length of the array, unless there was an error, in which case
this will throw an exception).

Wrapper around
[`lib.ssh_channel_write()`](@ref)/[`lib.ssh_channel_write_stderr()`](@ref).
"""
function Base.write(sshchan::SshChannel, data::Vector{UInt8}; stderr::Bool=false)
    if !isassigned(sshchan) || !isopen(sshchan)
        throw(ArgumentError("SshChannel has been closed, is not writeable"))
    end

    writer = stderr ? lib.ssh_channel_write_stderr : lib.ssh_channel_write

    GC.@preserve data begin
        ptr = Ptr{Cvoid}(pointer(data))
        ret = writer(sshchan.ptr, ptr, length(data))
    end
    if ret == SSH_ERROR
        throw(LibSSHException("Error when writing to channel: $(ret)"))
    end

    return Int(ret)
end

"""
$(TYPEDSIGNATURES)

Check if an EOF has been sent *by the remote end*. This does *not* imply that an
EOF has been sent from the local end and thus the channel is not writable (for
that, use [`iswritable(::SshChannel)`](@ref)). Check `SshChannel.local_eof` to
check if an EOF has been sent from the local end.

Wrapper around [`lib.ssh_channel_is_eof()`](@ref).
"""
function Base.eof(sshchan::SshChannel)
    if isassigned(sshchan)
        lib.ssh_channel_is_eof(sshchan.ptr) != 0
    else
        true
    end
end

"""
$(TYPEDSIGNATURES)

Check if the channel is writable.
"""
function Base.iswritable(sshchan::SshChannel)
    if isassigned(sshchan) && isopen(sshchan)
        !sshchan.local_eof
    else
        false
    end
end

"""
$(TYPEDSIGNATURES)

Wrapper around [`lib.ssh_set_channel_callbacks()`](@ref). Will throw a
[`LibSSHException`](@ref) if setting the callbacks failed.
"""
function set_channel_callbacks(sshchan::SshChannel, callbacks::Callbacks.ChannelCallbacks)
    ret = lib.ssh_set_channel_callbacks(sshchan.ptr, Ref(callbacks.cb_struct))
    if ret != SSH_OK
        throw(LibSSHException("Error when setting channel callbacks: $(ret)"))
    end
end

"""
$(TYPEDSIGNATURES)

Sends an EOF message. Wrapper around [`lib.ssh_channel_send_eof()`](@ref).

!!! warning
    Calling this function will trigger any waiting callbacks.
"""
function channel_send_eof(sshchan::SshChannel)
    # If we've already sent an EOF, do nothing
    if sshchan.local_eof
        return
    end

    if !iswritable(sshchan)
        throw(ArgumentError("SshChannel has been closed, cannot send EOF"))
    end

    ret = lib.ssh_channel_send_eof(sshchan.ptr)
    if ret != SSH_OK
        throw(LibSSHException("Error when sending EOF on channel: $(ret)"))
    end
    sshchan.local_eof = true
end

"""
$(TYPEDSIGNATURES)

Sends an exit status in reponse to an exec request. Wrapper around
[`lib.ssh_channel_request_send_exit_status()`](@ref).
"""
function channel_request_send_exit_status(sshchan::SshChannel, status::Int)
    if !isopen(sshchan)
        throw(ArgumentError("SshChannel has been closed, cannot send exit status"))
    end

    ret = lib.ssh_channel_request_send_exit_status(sshchan.ptr, Cint(status))
    if ret != SSH_OK
        throw(LibSSHException("Error when sending exit status on channel: $(ret)"))
    end
end

"""
$(TYPEDSIGNATURES)

Poll a (owning) channel in a loop while it's alive, which will trigger any
callbacks. This function should always be called on a channel for it to work
properly. It will return the last result from [`lib.ssh_channel_poll()`](@ref),
which should be checked to see if it's `SSH_EOF`.
"""
function poll_loop(sshchan::SshChannel)
    if !sshchan.owning
        throw(ArgumentError("Polling is only possible for owning SshChannel's, the passed channel is non-owning"))
    end

    ret = SSH_ERROR
    while true
        # Note that we don't actually read any data in this loop, that's
        # handled by the callbacks, which are called by ssh_channel_poll().
        ret = lib.ssh_channel_poll(sshchan.ptr, 0)

        # Break if there was an error, or if an EOF has been sent
        if ret == SSH_ERROR || ret == SSH_EOF
            break
        end

        wait(sshchan.session)
    end

    return Int(ret)
end

## execute()

function _log(msg, userdata)
    if userdata[:verbose]
        @info "execute(): $(msg)"
    end
end

function _on_channel_data(session, sshchan, data, is_stderr, userdata)
    is_stderr = Bool(is_stderr)
    fd_msg = is_stderr ? "stderr" : "stdout"
    _log("channel_data $(length(data)) bytes from $fd_msg", userdata)

    put!(userdata[:channel], copy(data))

    return length(data)
end

function _on_channel_eof(session, sshchan, userdata)
    _log("channel_eof", userdata)
end

function _on_channel_close(session, sshchan, userdata)
    _log("channel_close", userdata)
end

function _on_channel_exit_status(session, sshchan, ret, userdata)
    _log("exit_status $ret", userdata)
    userdata[:exit_code] = Int(ret)
end

"""
$(TYPEDSIGNATURES)

Execute `command` remotely. This will return a tuple of
`(return_code::Union{Int, Nothing}, output::String)`. The `return_code` may be
`nothing` if it wasn't sent by the server (which would point to an incorrect
server implementation).
"""
function execute(session::Session, command::AbstractString; verbose=false)
    userdata = Dict{Symbol, Any}(:channel => Channel(),
                                 :exit_code => nothing,
                                 :verbose => verbose)
    callbacks = Callbacks.ChannelCallbacks(userdata;
                                           on_eof=_on_channel_eof,
                                           on_close=_on_channel_close,
                                           on_data=_on_channel_data,
                                           on_exit_status=_on_channel_exit_status)

    SshChannel(session) do sshchan
        set_channel_callbacks(sshchan, callbacks)

        # Open the session
        ret = _session_trywait(session) do
            lib.ssh_channel_open_session(sshchan.ptr)
        end
        if ret != SSH_OK
            throw(LibSSHException("Failed to open a session channel: $(ret)"))
        end

        # Make the request
        ret = _session_trywait(session) do
            GC.@preserve command begin
                lib.ssh_channel_request_exec(sshchan.ptr, Base.unsafe_convert(Ptr{Cchar}, command))
            end
        end
        if ret != SSH_OK
            err = get_error(session)
            throw(LibSSHException("Error from channel_request_exec, could not execute command: $(err)"))
        end

        # Start a task to read incoming data and append it to a vector
        cmd_output = String[]
        reader_task = Threads.@spawn for data in userdata[:channel]
            try
                push!(cmd_output, String(data))
            catch ex
                @error "Error handling command output" exception=(ex, catch_backtrace())
            end
        end

        # Wait for data to be read
        ret = poll_loop(sshchan)

        # Close the reader task and send an EOF
        close(userdata[:channel])
        wait(reader_task)
        lib.ssh_channel_send_eof(sshchan.ptr)

        # Check the result of the read for an error
        if ret == SSH_ERROR
            throw(LibSSHException("Error while reading data from channel: $(ret)"))
        end

        return (userdata[:exit_code]::Union{Int, Nothing}, string(cmd_output...))
    end
end

## Direct port forwarding

# Handler for receiving data from the server
function _on_client_channel_data(session, sshchan, data, is_stderr, client)
    _logcb(client, "Received $(length(data)) bytes from server")

    write(client.sock, data)

    return length(data)
end

function _on_client_channel_eof(session, sshchan, client)
    _logcb(client, "EOF")

    close(client.sshchan)
    closewrite(client.sock)
    close(client.sock)
end

function _on_client_channel_close(session, sshchan, client)
    _logcb(client, "close")
end

# Handler for a single client on a forwarded port. It will take care of polling
# the channel and forwarding data to the server and client.
function _handle_forwarding_client(client)
    # Start polling the client channel
    poller = Threads.@spawn poll_loop(client.sshchan)

    # Read data from the socket while it's open
    sock = client.sock
    while isopen(sock)
        data = readavailable(sock)

        if !isempty(data) && isopen(client.sshchan)
            write(client.sshchan, data)
        elseif isempty(data) && eof(sock)
            close(sock)
            if iswritable(client.sshchan)
                channel_send_eof(client.sshchan)
            end
            close(client.sshchan)
        end
    end

    ret = fetch(poller)
    if ret == SSH_ERROR
        throw(LibSSHException("Error when polling Forwarder SshChannel: $ret"))
    end
end

# Struct to represent a client connected to a forwarded port
mutable struct _ForwardingClient
    const id::Int
    verbose::Bool

    sock::TCPSocket
    sshchan::SshChannel
    callbacks::Callbacks.ChannelCallbacks
    client_task::Union{Task, Nothing}
end

# Helper function to log messages from a forwarding client
function _logcb(client::_ForwardingClient, msg)
    if client.verbose
        timestamp = Dates.format(Dates.now(), Dates.ISOTimeFormat)
        @info "$timestamp _ForwardingClient $(client.id): $msg"
    end
end

function Base.close(client::_ForwardingClient)
    # Check if the socket is open in a try-catch, because isopen() will throw an
    # exception if the socket isn't initialized yet by libuv.
    sock_isopen = true
    try
        sock_isopen = isopen(client.sock)
    catch ex
        if ex isa ArgumentError
            sock_isopen = false
        else
            rethrow()
        end
    end

    if sock_isopen
        if iswritable(client.sock)
            closewrite(client.sock)
        end
        close(client.sock)
    end

    close(client.sshchan)
    wait(client.client_task)
end

"""
$(TYPEDEF)
$(TYPEDFIELDS)

This object manages a direct forwarding channel between `localport` and `remotehost:remoteport`.
"""
mutable struct Forwarder
    remotehost::String
    remoteport::Int
    localport::Int

    _listen_server::TCPServer
    _listener_task::Union{Task, Nothing}
    _clients::Vector{_ForwardingClient}

    _session::Session
    verbose::Bool

    @doc """
    $(TYPEDSIGNATURES)

    Create a `Forwarder` object to forward data from `localport` to
    `remotehost:remoteport`. This will handle an internal [`SshChannel`](@ref)
    for forwarding.
    """
    function Forwarder(session::Session, localport::Int, remotehost::String, remoteport::Int; verbose=false)
        listen_server = Sockets.listen(IPv4(0), localport)

        self = new(remotehost, remoteport, localport,
                   listen_server, nothing, _ForwardingClient[],
                   session, verbose)

        # Start the listener
        self._listener_task = Threads.@spawn try
            _fwd_listen(self)
        catch ex
            @error "Error in listen loop for Forwarder!" exception=(ex, catch_backtrace())
        end

        finalizer(close, self)
    end
end

"""
$(TYPEDSIGNATURES)

Do-constructor for a `Forwarder`. All arguments are forwarded to the
[`Forwarder(::Session, ::Int, ::String, ::Int)`](@ref) constructor.
"""
function Forwarder(f::Function, args...; kwargs...)
    forwarder = Forwarder(args...; kwargs...)

    try
        return f(forwarder)
    finally
        close(forwarder)
    end
end

"""
$(TYPEDSIGNATURES)

Close a `Forwarder`. This will close all client channels and the listening local
socket.
"""
function Base.close(forwarder::Forwarder)
    # Stop accepting new clients
    close(forwarder._listen_server)
    wait(forwarder._listener_task)

    # Close existing clients
    for client in forwarder._clients
        close(client)
    end
end

# This function accepts connections on the local port and sets up
# _ForwardingClient's for them.
function _fwd_listen(forwarder::Forwarder)
    next_client_id = 1
    remotehost = forwarder.remotehost
    remoteport = forwarder.remoteport

    while isopen(forwarder._listen_server)
        local sock
        try
            sock = Sockets.accept(forwarder._listen_server)
        catch ex
            if ex isa Base.IOError
                continue
            else
                rethrow()
            end
        end

        # Open a forwarding channel
        local_ip = string(getaddrinfo(gethostname()))
        sshchan = SshChannel(forwarder._session)
        ret = _session_trywait(forwarder._session) do
            GC.@preserve remotehost local_ip begin
                lib.ssh_channel_open_forward(sshchan.ptr,
                                             Base.unsafe_convert(Ptr{Cchar}, remotehost), remoteport,
                                             Base.unsafe_convert(Ptr{Cchar}, local_ip), forwarder.localport)
            end
        end
        if ret != SSH_OK
            throw(LibSSHException("Could not open a forwarding channel: $(get_error(forwarder._session))"))
        end

        # Set callbacks for the channel
        callbacks = Callbacks.ChannelCallbacks(nothing;
                                               on_data=_on_client_channel_data,
                                               on_eof=_on_client_channel_eof,
                                               on_close=_on_client_channel_close)
        set_channel_callbacks(sshchan, callbacks)

        # Create a client and set the callbacks userdata to the new client object
        client = _ForwardingClient(next_client_id, forwarder.verbose, sock,
                                   sshchan, callbacks, nothing)
        callbacks.userdata = client

        # Start a listener on the new socket to forward data to the server
        client.client_task = Threads.@spawn try
            _handle_forwarding_client(client)
        catch ex
            @error "Error when handling SSH port forward client $(client.id)!" exception=(ex, catch_backtrace())
        end

        push!(forwarder._clients, client)
        next_client_id += 1
    end
end
