mutable struct SshChannel
    ptr::Union{lib.ssh_channel, Nothing}
end

"""
$(TYPEDSIGNATURES)
"""
function SshChannel(session::Session)
    if !isconnected(session)
        throw(ArgumentError("Cannot create a SshChannel on an unconnected Session"))
    end

    ptr = lib.ssh_channel_new(session.ptr)
    if ptr == C_NULL
        throw(LibSSHException("Could not allocate ssh_channel"))
    end

    self = SshChannel(ptr)
    finalizer(close, self)
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

Closes the channel, and then frees its memory.
"""
function Base.close(sshchan::SshChannel)
    if !isnothing(sshchan.ptr) && isopen(sshchan)
        lib.ssh_channel_close(sshchan.ptr)
        lib.ssh_channel_free(sshchan.ptr)
        sshchan.ptr = nothing
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
