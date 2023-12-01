mutable struct SshChannel
    ptr::lib.ssh_channel

    function SshChannel(session::Session)
        if !isconnected(session)
            throw(ArgumentError("Cannot create a SshChannel on an unconnected Session"))
        end

        ptr = lib.ssh_channel_new(session.ptr)
        if ptr == C_NULL
            throw(LibSSHException("Could not allocate ssh_channel"))
        end

        self = new(ptr)
        finalizer(close, self)
    end
end

Base.isopen(sshchan::SshChannel) = lib.ssh_channel_is_open(sshchan.ptr) != 0

function Base.close(sshchan::SshChannel)
    if isopen(sshchan)
        lib.ssh_channel_close(sshchan)
        lib.ssh_channel_free(sshchan.ptr)
    end
end
