"""
$(TYPEDEF)
$(TYPEDFIELDS)

Wraps a `LibSSH.lib.ssh_channel`. An `SshChannel` can be owning or non-owning
of a pointer to the underlying `lib.ssh_channel`, and only owning `SshChannel`s
can be closed with `close()`.

!!! warning
    Make sure that `close(::SshChannel)` isn't called during the execution of
    `ssh.event_dopoll()`, or you will get deeply mystifying segfaults. The best
    way to prevent this is by passing in the `SshChannel.close_lock` of each
    channel like so:
    ```julia
    ssh.event_dopoll(event, session, sshchan1.close_lock, sshchan2.close_lock)
    ```

    This will lock the channels during the execution of any channel callbacks by
    `ssh.event_dopoll()`.
"""
mutable struct SshChannel
    ptr::Union{lib.ssh_channel, Nothing}
    owning::Bool
    session::Union{Session, Nothing}
    close_lock::ReentrantLock

    function SshChannel(ptr::lib.ssh_channel, session=nothing; own=true)
        self = new(ptr, own, session, ReentrantLock())
        if own
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
data = SshChannel(session) do sshchan
    return 42
end

@test data == 42
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

Checks if the channel is open. Wrapper around `LibSSH.lib.ssh_channel_is_open()`.
"""
function Base.isopen(sshchan::SshChannel)
    if isnothing(sshchan.ptr)
        false
    else
        lib.ssh_channel_is_open(sshchan.ptr) != 0
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

    @lock sshchan.close_lock begin
        if !isnothing(sshchan.ptr)
            if !isopen(sshchan.session::Session)
                error("The session of the SshChannel has already been closed, won't close/free the channel to avoid a segfault (this is a memory leak!)")
            end

            if isopen(sshchan)
                ret = lib.ssh_channel_close(sshchan.ptr)
                if ret != SSH_OK
                    throw(LibSSHException("Closing SshChannel failed: $(ret)"))
                end
            end

            lib.ssh_channel_free(sshchan.ptr)
            sshchan.ptr = nothing
        end
    end
end

"""
$(TYPEDSIGNATURES)

Write data to the channel and return the number of code units written. Wrapper
around `LibSSH.lib.ssh_channel_write{_stderr}()`.
"""
function Base.write(sshchan::SshChannel, data::AbstractString; stderr::Bool=false)
    if isnothing(sshchan) || !isopen(sshchan)
        throw(ArgumentError("SshChannel has been closed, is not writeable"))
    end

    writer = stderr ? lib.ssh_channel_write_stderr : lib.ssh_channel_write

    ptr = Ptr{Cvoid}(pointer(data))
    ret = writer(sshchan.ptr, ptr, ncodeunits(data))
    if ret == SSH_ERROR
        throw(LibSSHException("Error when writing to channel: $(ret)"))
    end

    return Int(ret)
end

"""
$(TYPEDSIGNATURES)

Check if an EOF has been sent by the remote end. Wrapper around
`LibSSH.lib.ssh_channel_is_eof()`.
"""
function Base.eof(sshchan::SshChannel)
    if isnothing(sshchan.ptr)
        true
    else
        lib.ssh_channel_is_eof(sshchan.ptr) != 0
    end
end

"""
$(TYPEDSIGNATURES)

Sends an EOF message. Wrapper around `LibSSH.lib.ssh_channel_send_eof()`.
"""
function channel_send_eof(sshchan::SshChannel)
    if isnothing(sshchan.ptr)
        throw(ArgumentError("SshChannel has been closed, cannot send EOF"))
    end

    ret = lib.ssh_channel_send_eof(sshchan.ptr)
    if ret != SSH_OK
        throw(LibSSHException("Error when sending EOF on channel: $(ret)"))
    end
end

"""
$(TYPEDSIGNATURES)

Sends an exit status in reponse to an exec request. Wrapper around
`LibSSH.lib.ssh_channel_request_send_exit_status()`.
"""
function channel_request_send_exit_status(sshchan::SshChannel, status::Int)
    if isnothing(sshchan.ptr)
        throw(ArgumentError("SshChannel has been closed, cannot send exit status"))
    end

    ret = lib.ssh_channel_request_send_exit_status(sshchan.ptr, Cint(status))
    if ret != SSH_OK
        throw(LibSSHException("Error when sending exit status on channel: $(ret)"))
    end
end

## execute()

function _log(msg, userdata)
    if userdata[:verbose]
        @info "execute(): $(msg)"
    end
end

function _on_channel_data(session, sshchan, data_ptr::Ptr{Cvoid}, nbytes, is_stderr, userdata)
    is_stderr = Bool(is_stderr)
    fd_msg = is_stderr ? "stderr" : "stdout"
    _log("channel_data $nbytes bytes from $fd_msg", userdata)

    data = unsafe_wrap(Array, Ptr{UInt8}(data_ptr), nbytes)
    put!(userdata[:channel], copy(data))

    return nbytes
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
                                           channel_write_wontblock_function=(session, sshchan, sz, userdata) -> 0,
                                           channel_eof_function=_on_channel_eof,
                                           channel_close_function=_on_channel_close,
                                           channel_data_function=_on_channel_data,
                                           channel_exit_status_function=_on_channel_exit_status)

    SshChannel(session) do sshchan
        Callbacks.set_channel_callbacks(sshchan, callbacks)

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
        ret::Cint = Cint(0)
        while true
            # Note that we don't actually read any data in this loop, that's
            # handled by the callbacks, which are called by ssh_channel_poll().
            ret = lib.ssh_channel_poll(sshchan.ptr, 0)

            # Break if there was an error, or an EOF has been sent
            if ret == SSH_ERROR || ret == SSH_EOF
                break
            end

            wait(session)
        end

        # Close the reader task and send an EOF
        close(userdata[:channel])
        wait(reader_task)
        lib.ssh_channel_send_eof(sshchan.ptr)

        # Check the result of the read for an error
        if ret == SSH_ERROR
            throw(LibSSHException("Error while reading data from channel: $(ret)"))
        end

        return (userdata[:exit_code], string(cmd_output...))
    end
end
