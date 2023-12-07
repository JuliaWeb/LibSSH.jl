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
    close_lock::ReentrantLock

    function SshChannel(ptr::lib.ssh_channel; own=true)
        self = new(ptr, own, ReentrantLock())
        if own
            finalizer(_finalizer, self)
        end

        return self
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
        throw(LibSSHException("Could not allocate ssh_channel"))
    end

    return SshChannel(ptr)
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
    if !sshchan.owning
        throw(ArgumentError("Calling close() on a non-owning SshChannel is not allowed to avoid accidental double-frees, see the docs for more information."))
    end

    @lock sshchan.close_lock begin
        if !isnothing(sshchan.ptr)
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

function channel_request_send_exit_status(sshchan::SshChannel, status::Int)
    if isnothing(sshchan.ptr)
        throw(ArgumentError("SshChannel has been closed, cannot send exit status"))
    end

    ret = lib.ssh_channel_request_send_exit_status(sshchan.ptr, Cint(status))
    if ret != SSH_OK
        throw(LibSSHException("Error when sending exit status on channel: $(ret)"))
    end
end
