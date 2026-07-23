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

!!! warning
    `SshChannel`'s *must* be closed explicitly with
    [`Base.close(::SshChannel)`](@ref). There is no finalizer, so failing to
    close an `SshChannel` will leak resources.
"""
mutable struct SshChannel
    ptr::Union{lib.ssh_channel, Nothing}
    owning::Bool
    session::Union{Session, Nothing}
    close_lock::ReentrantLock
    local_eof::Bool
    callbacks::Union{ChannelCallbacks, Nothing}
    _pending_close::Bool
    # Set once the actor has observed the channel open, so it can tell a
    # not-yet-opened channel apart from one that opened and then closed.
    _poll_seen_open::Bool
    # Carries the terminating ssh_channel_poll() result to wait(::SshChannel)
    # (or nothing if the channel/session closed). Buffered so the result is
    # kept even if nobody is waiting yet.
    _poll_done::Channel{Union{Int, Nothing}}

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
        elseif own && !isnothing(session) && !session.owning
            throw(ArgumentError("Cannot create a SshChannel from a non-owning Session"))
        end
        self = new(ptr, own, session, ReentrantLock(), false, nothing, false,
                   false, Channel{Union{Int, Nothing}}(1))

        if own
            push!(session.closeables, self)
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

    ptr = _session_call(session, () -> lib.ssh_channel_new(session))
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

function Base.unsafe_convert(::Type{lib.ssh_channel}, sshchan::SshChannel)
    if !isassigned(sshchan)
        throw(ArgumentError("SshChannel is unassigned, cannot get a pointer from it"))
    end

    return sshchan.ptr
end

function Base.show(io::IO, sshchan::SshChannel)
    print(io, SshChannel, "(ptr=$(sshchan.ptr), owning=$(sshchan.owning))")
end

"""
$(TYPEDSIGNATURES)

Check if the channel holds a valid pointer to a `lib.ssh_channel`.
"""
Base.isassigned(sshchan::SshChannel) = !isnothing(sshchan.ptr)

"""
$(TYPEDSIGNATURES)

Checks if the channel is open. Wrapper around
[`lib.ssh_channel_is_open()`](@ref).
"""
function Base.isopen(sshchan::SshChannel)
    if isassigned(sshchan)
        if isnothing(sshchan.session)
            lib.ssh_channel_is_open(sshchan) != 0
        elseif isconnected(sshchan.session)
            _session_call(sshchan.session, () -> isassigned(sshchan) && lib.ssh_channel_is_open(sshchan) != 0)
        else
            false
        end
    else
        false
    end
end

# Request that the channel be closed after the current libssh callback returns.
# This must be used instead of close(::SshChannel) when closing a channel from
# inside a channel callback (e.g. `on_eof`, `on_close`). Calling `close()`
# directly from a callback will free the callback list that libssh is currently
# iterating, causing a segfault.  The actual close will be performed by the
# actor's channel poll or event_dopoll(::SessionEvent) after the C call returns.
function defer_close(sshchan::SshChannel)
    sshchan._pending_close = true
end

# Close any channels that had defer_close() called on them
function _do_deferred_channel_closes(session::Session)
    for obj in copy(session.closeables)
        if obj isa SshChannel && obj._pending_close
            obj._pending_close = false
            close(obj; allow_fail=true)
        end
    end
end

"""
$(TYPEDSIGNATURES)

Closes the channel, and then frees its memory. To avoid the risk of
double-frees, this function may only be called on *owning* `SshChannel`s. It
will hold the `close_lock` of the channel during execution.

# Arguments
- `sshchan`: The [`SshChannel`](@ref) to close.
- `allow_fail=false`: Whether to throw an exception if the call to
  [`lib.ssh_channel_close()`](@ref) fails. In some cases it can fail for valid
  reasons, such as the socket already having been closed by the other end (this
  will result in a `Socket error: disconnected` error).
"""
function Base.close(sshchan::SshChannel; allow_fail=false)
    if !sshchan.owning
        throw(ArgumentError("Calling close() on a non-owning SshChannel is not allowed to avoid accidental double-frees, see the docs for more information."))
    end

    # Stop the actor polling this channel and unblock any wait(::SshChannel).
    _finish_channel_poll(sshchan, nothing)

    @lock sshchan.close_lock begin
        # Even though we hold a lock in this section it's still possible for the
        # function to be called recursively and enter it again anyway. The reason is
        # because lib.ssh_channel_send_eof() and lib.ssh_channel_close() both flush
        # the channel, which will trigger any callbacks. And if the callbacks happen
        # to call close(), then the lock will be taken anyway (because it's a
        # reentrant lock). There's not much we can do about this apart from making
        # close() as robust as possible, which is why there are so many checks.

        if isassigned(sshchan)
            session_closed = false

            # Remove from the sessions list of active channels. findfirst()
            # should only return nothing if the function is being called
            # recursively (i.e. through a callback) and it was already removed.
            idx = findfirst(x -> x === sshchan, sshchan.session.closeables)
            if !isnothing(idx)
                popat!(sshchan.session.closeables, idx)
            end

            if !isnothing(sshchan.session) && !isconnected(sshchan.session)
                # If the session has already been disconnected from C
                # (e.g. because of the other side disconnecting) then that will
                # already have free'd the channel, which means we only need to
                # unassign the pointer.
                sshchan.ptr = nothing
            elseif isopen(sshchan)
                # This will trigger callbacks
                closewrite(sshchan; allow_fail)

                # This will trigger callbacks
                ret = SSH_ERROR
                try
                    ret = _session_call(sshchan.session, () -> lib.ssh_channel_close(sshchan))
                catch ex
                    if ex isa LibSSHException && ex.msg == "Session is closed"
                        # If the session is closed then so is the channel so we
                        # don't need to do anything.
                        session_closed = true
                    else
                        rethrow()
                    end
                end

                if ret != SSH_OK && !session_closed
                    msg = "Closing SshChannel failed with $(ret): '$(get_error(sshchan.session))'"
                    if allow_fail
                        # Note that we spawn to avoid task switches
                        @warn msg
                    else
                        throw(LibSSHException(msg))
                    end
                end
            end

            # Free the memory
            if isassigned(sshchan)
                if !session_closed
                    _session_call(sshchan.session, () -> lib.ssh_channel_free(sshchan))
                end

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

Write a byte array to the channel and return the number of bytes written. In
most cases this should match the length of the array, unless there was an error,
in which case this will throw an exception.

If the remote receive window is 0 then it will retry for `timeout` seconds
before throwing an exception (pass -1 to disable the timeout). Note that this
does not mean the total possible time to write the whole message is `timeout`
seconds, but rather that we give the server `timeout` seconds to be ready each
time it says it can't receive more data (which could be multiple times per
message).

Wrapper around
[`lib.ssh_channel_write()`](@ref)/[`lib.ssh_channel_write_stderr()`](@ref).
"""
function Base.write(sshchan::SshChannel, data::Vector{UInt8}; stderr::Bool=false, timeout=30)
    if !isassigned(sshchan) || !isopen(sshchan)
        throw(ArgumentError("SshChannel has been closed, is not writeable"))
    end

    writer = stderr ? lib.ssh_channel_write_stderr : lib.ssh_channel_write

    deadline = time() + (timeout < 0 ? Inf : timeout)
    written = 0
    total = length(data)
    while written < total
        ret = GC.@preserve data begin
            ptr = Ptr{Cvoid}(pointer(data) + written)
            _session_call(sshchan.session, () -> writer(sshchan, ptr, total - written))
        end

        if ret == SSH_ERROR
            throw(LibSSHException("Error when writing to channel: $(ret)"))
        elseif ret > 0
            # Reset the deadline when we successfully write
            deadline = time() + (timeout < 0 ? Inf : timeout)
        end

        written += ret
        if written < total
            try
                wait(sshchan.session)
            catch ex
                # The session was closed underneath us (shutdown or a dropped
                # socket), fall through to the short-write exception below.
                if ex isa InvalidStateException || ex isa Base.IOError
                    break
                else
                    rethrow()
                end
            end
        end

        if time() > deadline
            break
        end
    end

    if written < total
        throw(LibSSHException("Could not write all data to $(sshchan) of $(sshchan.session): $(written)/$(total) bytes written"))
    end

    return written
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
    if isassigned(sshchan) && !isnothing(sshchan.session)
        _session_call(sshchan.session, () -> lib.ssh_channel_is_eof(sshchan) != 0)
    elseif isassigned(sshchan)
        lib.ssh_channel_is_eof(sshchan) != 0
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

Wrapper around [`lib.ssh_set_channel_callbacks()`](@ref) and
[`lib.ssh_remove_channel_callbacks()`](@ref). Unlike
[`lib.ssh_set_channel_callbacks()`](@ref) this will replace any existing
callbacks.

# Throws
- [`LibSSHException`](@ref): If setting the callbacks failed.
"""
function set_channel_callbacks(sshchan::SshChannel, callbacks::ChannelCallbacks)
    if !isnothing(sshchan.callbacks)
        remove_channel_callbacks(sshchan, sshchan.callbacks)
    end

    ret = _session_call(sshchan.session, () -> lib.ssh_set_channel_callbacks(sshchan, Ref(callbacks.cb_struct)))
    if ret != SSH_OK
        throw(LibSSHException("Error when setting channel callbacks: $(ret)"))
    end
    sshchan.callbacks = callbacks

    # The channel now wants to receive data, so have the actor poll it
    # automatically (it may not be open yet — the actor waits for that).
    # Server sessions are excluded: they drive I/O via event_dopoll(), not the
    # actor, so the two would fight over the same channel.
    if sshchan.owning && isnothing(sshchan.session.server_callbacks)
        _register_channel_poll(sshchan)
    end
end

# Undocumented for now because the API for setting callbacks isn't fleshed out yet
function remove_channel_callbacks(sshchan::SshChannel, callbacks::ChannelCallbacks)
    _finish_channel_poll(sshchan, nothing)

    ret = _session_call(sshchan.session, () -> lib.ssh_remove_channel_callbacks(sshchan, Ref(callbacks.cb_struct)))
    if ret != SSH_OK
        throw(LibSSHException("Error when removing channel callbacks: $(ret)"))
    end
    sshchan.callbacks = nothing
end

"""
$(TYPEDSIGNATURES)

Sends an EOF message. Calling this function will trigger any waiting callbacks.

# Throws
- `ArgumentError`: if the channel is not writable.

Wrapper around [`lib.ssh_channel_send_eof()`](@ref).

# Arguments
- `sshchan`: The [`SshChannel`](@ref) to send an EOF on.
- `allow_fail=false`: Whether to throw an exception if the call to
  [`lib.ssh_channel_send_eof()`](@ref) fails. In some cases it can fail for
  valid reasons, such as the socket already having been closed by the other end
  (this will result in a `Socket error: disconnected` error).
"""
function Base.closewrite(sshchan::SshChannel; allow_fail=false)
    # If we've already sent an EOF, do nothing
    if sshchan.local_eof
        return
    end

    if !iswritable(sshchan)
        if allow_fail
            return
        end
        throw(ArgumentError("SshChannel has been closed, cannot send EOF"))
    end

    ret = _session_call(sshchan.session, () -> lib.ssh_channel_send_eof(sshchan))
    if ret != SSH_OK
        error_msg = get_error(sshchan.session)
        if allow_fail
            @warn "closewrite() on SshChannel failed: '$(error_msg)'"
        else
            throw(LibSSHException("Error when sending EOF on channel: '$(error_msg)'"))
        end
    end

    sshchan.local_eof = true
end

"""
$(TYPEDSIGNATURES)

Sends an exit status in reponse to an exec request. Wrapper around
[`lib.ssh_channel_request_send_exit_status()`](@ref).
"""
function channel_request_send_exit_status(sshchan::SshChannel, status::Integer)
    if !isopen(sshchan)
        throw(ArgumentError("SshChannel has been closed, cannot send exit status"))
    end

    ret = _session_call(sshchan.session, () -> lib.ssh_channel_request_send_exit_status(sshchan, Cint(status)))
    if ret != SSH_OK
        throw(LibSSHException("Error when sending exit status on channel: $(ret)"))
    end
end

# Register a channel so the session's actor task polls it directly (which
# triggers its callbacks) after each fd poll. This replaces the old per-channel
# poll_loop task: there is no extra task and no _session_call round-trip per
# SSH chunk. Called automatically by set_channel_callbacks().
function _register_channel_poll(sshchan::SshChannel)
    session = sshchan.session
    @lock session._wakeup push!(session._poll_regs, sshchan)

    # Kick the actor out of a blocking take!(requests)/_poll_fd so it notices
    # the new registration and starts polling.
    _wake_actor(session)
end

# Deliver the terminating poll result to wait(::SshChannel) and unregister the
# channel. Exactly-once: only the call that removes it from _poll_regs delivers
# (the actor on EOF/ERROR, or close()/remove_channel_callbacks()/actor exit).
function _finish_channel_poll(sshchan::SshChannel, value::Union{Int, Nothing})
    session = sshchan.session
    if isnothing(session)
        return
    end

    @lock session._wakeup begin
        idx = findfirst(x -> x === sshchan, session._poll_regs)
        if !isnothing(idx)
            popat!(session._poll_regs, idx)
            # Only the call that removes the registration delivers, so this
            # runs exactly once on the (empty) one-shot channel.
            try
                put!(sshchan._poll_done, value)
            catch
            end
        end
    end
end

# Run on the actor task after the session fd is polled: poll each registered
# channel (triggering its callbacks) and finish any that hit EOF/ERROR. This is
# the work the old poll_loop task did via _session_call, now done inline on the
# task that already owns the C calls.
function _actor_poll_channels(session::Session)
    channels = @lock session._wakeup copy(session._poll_regs)
    for sshchan in channels
        # We're the actor, so call libssh directly rather than through
        # isopen()/_session_call (which would deadlock on ourselves).
        opened = isassigned(sshchan) && lib.ssh_channel_is_open(sshchan) != 0

        if !opened
            # A channel registered before it was opened (e.g. execute()) just
            # waits here until it opens; one that was open and is now closed
            # is finished.
            if sshchan._poll_seen_open
                _finish_channel_poll(sshchan, nothing)
            end
            continue
        end
        sshchan._poll_seen_open = true

        # We don't read any data here, that's handled by the callbacks invoked
        # by ssh_channel_poll().
        r = lib.ssh_channel_poll(sshchan, 0)
        if r != SSH_ERROR && r != SSH_EOF && !sshchan._pending_close
            r = lib.ssh_channel_poll(sshchan, 1)
        end

        # Apply deferred closes requested by callbacks during the poll. We
        # can't close here (close_lock could deadlock with an external close()
        # waiting on the actor), so we signal the waiter to exit and let it
        # close the channel externally.
        if sshchan._pending_close
            sshchan._pending_close = false
            r = SSH_EOF
        end

        if r == SSH_ERROR || r == SSH_EOF
            _finish_channel_poll(sshchan, Int(r))
        end
    end
end

# Unblock all wait(::SshChannel) callers when the actor stops.
function _finish_poll_regs(session::Session)
    channels = @lock session._wakeup copy(session._poll_regs)
    for sshchan in channels
        _finish_channel_poll(sshchan, nothing)
    end
end

"""
$(TYPEDSIGNATURES)

Wait until an owning channel finishes (its remote end sends EOF, an error
occurs, or it is closed). Returns `nothing` if the channel/session was closed
before EOF, otherwise the terminating [`lib.ssh_channel_poll()`](@ref) result.

# Throws
- [`LibSSHException`](@ref): If `SSH_ERROR` is returned and `throw=true`.

# Arguments
- `sshchan`: The [`SshChannel`](@ref) to wait on.
- `throw=true`: Whether to throw an exception if `SSH_ERROR` is returned.
"""
function Base.wait(sshchan::SshChannel; throw=true)
    if !sshchan.owning
        Base.throw(ArgumentError("Waiting is only possible for owning SshChannel's, the passed channel is non-owning"))
    end

    # Not registered and no buffered result: the channel was never activated
    # (no callbacks set), so there is nothing to wait for.
    registered = !isnothing(sshchan.session) &&
        @lock sshchan.session._wakeup !isnothing(findfirst(x -> x === sshchan, sshchan.session._poll_regs))
    if !registered && !isready(sshchan._poll_done)
        return nothing
    end

    ret = try
        take!(sshchan._poll_done)
    catch
        nothing
    end

    if isnothing(ret)
        return nothing
    end

    if ret == Int(SSH_ERROR) && throw
        Base.throw(LibSSHException("SSH_ERROR returned from lib.ssh_channel_poll()"))
    end

    return ret
end

## execute()

function _log(msg, process)
    if process._verbose
        @info "execute(): $(msg)"
    end
end

function _on_channel_data(session, sshchan, data, is_stderr, process)
    is_stderr = Bool(is_stderr)
    fd_msg = is_stderr ? "stderr" : "stdout"
    _log("channel_data $(length(data)) bytes from $fd_msg", process)

    append!(is_stderr ? process.err : process.out, data)

    return length(data)
end

function _on_channel_eof(session, sshchan, process)
    _log("channel_eof", process)
end

function _on_channel_close(session, sshchan, process)
    _log("channel_close", process)
end

function _on_channel_exit_status(session, sshchan, ret, process)
    _log("exit_status $ret", process)
    process.exitcode = Int(ret)
end

"""
$(TYPEDEF)
$(TYPEDFIELDS)

This is analogous to `Base.Process`, it represents a command running over an
SSH session. The stdout and stderr output are stored as byte arrays in
`SshProcess.out` and `SshProcess.err` respectively. They can be converted to
strings using e.g. `String(copy(process.out))`.
"""
@kwdef mutable struct SshProcess
    out::Vector{UInt8} = Vector{UInt8}()
    err::Vector{UInt8} = Vector{UInt8}()

    cmd::Union{Cmd, String, Nothing} = nothing
    exitcode::Int = typemin(Int)

    _sshchan::Union{SshChannel, Nothing} = nothing
    _task::Union{Task, Nothing} = nothing
    _verbose::Bool = false
end

function Base.show(io::IO, process::SshProcess)
    status = process_running(process) ? "ProcessRunning" : "ProcessExited($(process.exitcode))"
    print(io, SshProcess, "(cmd=$(process.cmd), $status)")
end

Base.process_running(process::SshProcess) = !istaskdone(process._task)
Base.process_exited(process::SshProcess) = istaskdone(process._task)

"""
$(TYPEDSIGNATURES)

Check if the process succeeded.
"""
Base.success(process::SshProcess) = process_exited(process) && process.exitcode == 0

"""
$(TYPEDSIGNATURES)

# Throws
- [`SshProcessFailedException`](@ref): if `ignorestatus()` wasn't used.
"""
function Base.wait(process::SshProcess)
    try
        wait(process._task)
    catch task_ex
        ex = process._task.exception

        # The idea is that SshProcessFailedException's and LibSSHException's are
        # somewhat expected so we always unwrap them from the
        # TaskFailedException before throwing, which is a slightly nicer API to
        # work with.
        if ex isa SshProcessFailedException || ex isa LibSSHException
            if !(process.cmd isa Cmd && process.cmd.ignorestatus)
                throw(process._task.exception)
            end
        else
            rethrow()
        end
    end
end

"""
$(TYPEDEF)
$(TYPEDFIELDS)

This is analogous to `ProcessFailedException`.
"""
struct SshProcessFailedException <: Exception
    process::SshProcess
end

function _exec_command(process::SshProcess)
    sshchan = process._sshchan
    session = sshchan.session
    is_cmd = process.cmd isa Cmd
    cmd_str = is_cmd ? Base.shell_escape(process.cmd) : process.cmd

    # Open the session channel
    ret = _session_trywait(session) do
        lib.ssh_channel_open_session(sshchan)
    end
    if ret != SSH_OK
        throw(LibSSHException("Failed to open a session channel: $(ret)"))
    end

    # Set environment variables
    if is_cmd && !isnothing(process.cmd.env)
        for env_var in process.cmd.env
            # We explicitly convert the SubString's returned from split() to
            # String's so that they're each separate and null-terminated in
            # memory, otherwise the entire 'name=value' string would be sent
            # when we send `name`.
            name, value = String.(split(env_var, "="))
            ret = _session_trywait(session) do
                lib.ssh_channel_request_env(sshchan, name, value)
            end

            if ret != SSH_OK
                err = get_error(session)
                throw(LibSSHException("Error from lib.ssh_channel_request_env(), could not set environment variable '$(env_var)': '$(err)'. Hint: check that the server has an `AcceptEnv` config that allows setting this variable, otherwise it will fail."))
            end
        end
    end

    # Make the request
    ret = _session_trywait(session) do
        GC.@preserve cmd_str begin
            lib.ssh_channel_request_exec(sshchan, Base.unsafe_convert(Ptr{Cchar}, cmd_str))
        end
    end
    if ret != SSH_OK
        err = get_error(session)
        throw(LibSSHException("Error from lib.ssh_channel_request_exec, could not execute command: $(err)"))
    end

    # The actor polls the channel automatically (callbacks were set in
    # execute()); wait for it to finish reading.
    ret = wait(sshchan)

    # Close the channel
    if iswritable(sshchan)
        closewrite(sshchan)
    end
    close(sshchan)

    # Check the result of the read for an error
    if ret == SSH_ERROR
        throw(LibSSHException("Error while reading data from channel: $(ret)"))
    end

    if (!is_cmd || !process.cmd.ignorestatus) && process.exitcode != 0
        throw(SshProcessFailedException(process))
    end
end

"""
$(TYPEDSIGNATURES)

Run a command on the remote host over an SSH session. Things that aren't
supported compared to `run()`:
- Pipelined commands (use a regular pipe like `foo | bar` instead).
- Setting the directory to execute the command in.

An easy way of getting around these restrictions is to pass the command as a
`String` instead of `Cmd`.

!!! note
    Setting environment variables is supported, but will fail if the server
    forbids setting them.

# Throws
- [`SshProcessFailedException`](@ref): if the command fails and `ignorestatus()`
  wasn't used.
- [`LibSSHException`](@ref): if running the command fails for some other
  reason.

# Arguments
- `cmd`: The command to run. This will be converted to a string for running
  remotely.
- `session`: The session to run the command over.
- `wait=true`: Wait for the command to finish before returning.
- `verbose=false`: Print debug logging messages. Note that this is not the same
  as setting the `log_verbosity` on a [`Session`](@ref).
- `combine_outputs=true`: Write the `stderr` command output to the `IOBuffer`
  for the commands `stdout`. If this is `true` then `SshProcess.out` and
  `SshProcess.err` will refer to the same object.
- `print_out=true`: Print the output (stdout + stderr by default) of the
  command.

# Examples
```julia-repl
julia> import LibSSH as ssh

julia> ssh.DemoServer(2222; password="foo") do
           session = ssh.Session("127.0.0.1", 2222)
           @assert ssh.userauth_password(session, "foo") == ssh.AuthStatus_Success

           @info "1"
           run(`echo foo`, session)

           println()
           @info "2"
           run(ignorestatus(`foo`), session)

           println()
           @info "3"
           # Pass a string to avoid hacking around Cmd syntax
           run("cd /tmp && pwd", session)
       end
[ Info: 1
foo

[ Info: 2
sh: line 1: foo: command not found

[ Info: 3
/tmp
```
"""
function Base.run(cmd::Union{Cmd, String}, session::Session;
                  wait::Bool=true, verbose::Bool=false,
                  combine_outputs::Bool=true, print_out::Bool=true)
    process = SshProcess(; cmd, _verbose=verbose)
    if combine_outputs
        process.err = process.out
    end

    callbacks = ChannelCallbacks(process;
                                 on_eof=_on_channel_eof,
                                 on_close=_on_channel_close,
                                 on_data=_on_channel_data,
                                 on_exit_status=_on_channel_exit_status)
    process._sshchan = SshChannel(session)
    set_channel_callbacks(process._sshchan, callbacks)

    process._task = Threads.@spawn _exec_command(process)

    if wait
        # Note the use of Base.wait() to avoid aliasing with the `wait` argument
        Base.wait(process)

        if print_out
            print(String(copy(process.out)))
        end
    end

    return process
end

"""
$(TYPEDSIGNATURES)

Read the output from the command in bytes.
"""
function Base.read(cmd::Union{Cmd, String}, session::Session)
    process = run(cmd, session; print_out=false)
    return process.out
end

"""
$(TYPEDSIGNATURES)

Read the output from the command as a String.

# Examples
```julia-repl
julia> import LibSSH as ssh

julia> ssh.DemoServer(2222; password="foo") do
           session = ssh.Session("127.0.0.1", 2222)
           @assert ssh.userauth_password(session, "foo") == ssh.AuthStatus_Success

           @show read(`echo foo`, session, String)
       end
read(`echo foo`, session, String) = "foo\\n"
```
"""
Base.read(cmd::Union{Cmd, String}, session::Session, ::Type{String}) = String(read(cmd, session))

"""
$(TYPEDSIGNATURES)

`readchomp()` for remote commands.
"""
Base.readchomp(cmd::Union{Cmd, String}, session::Session) = chomp(read(cmd, session, String))

"""
$(TYPEDSIGNATURES)

Check the command succeeded.
"""
Base.success(cmd::Union{Cmd, String}, session::Session) = success(run(cmd, session; print_out=false))

## Direct port forwarding

# Handler for receiving data from the server
function _on_client_channel_data(session, sshchan, data, is_stderr, client)
    _logcb(client, "Received $(length(data)) bytes from server")

    if isopen(client.sock)
        write(client.sock, data)
    else
        @warn "Client socket has been closed, dropping $(length(data)) bytes from the remote forwarded port"
    end

    return length(data)
end

function _on_client_channel_eof(session, sshchan, client)
    _logcb(client, "EOF")

    # Defer the channel close to avoid freeing libssh's callback list while
    # it is being iterated (which would cause a segfault).
    if isopen(client.sock)
        closewrite(client.sock)
        close(client.sock)
    end
end

function _on_client_channel_close(session, sshchan, client)
    _logcb(client, "close")
end

# Handler for a single client on a forwarded port. The channel→socket
# direction is driven automatically by the session actor (callbacks were set
# in the _ForwardingClient constructor); this only forwards socket→channel.
function _handle_forwarding_client(client)
    # Read data from the socket while it's open
    sock = client.sock
    while isopen(sock)
        local data
        try
            # This will throw an IOError if the socket is closed during the read
            data = readavailable(sock)
        catch ex
            if ex isa Base.IOError
                continue
            else
                rethrow()
            end
        end

        if !isempty(data)
            try
                write(client.sshchan, data)
            catch ex
                if !isopen(client.sshchan)
                    break
                end

                rethrow()
            end
        elseif isempty(data) && eof(sock)
            close(sock)
            closewrite(client.sshchan; allow_fail=true)
            defer_close(client.sshchan)
        end
    end

    # Ensure the channel is closed. Some read loop exit paths (e.g. IOError on
    # the socket) don't call defer_close().
    if isopen(client.sshchan)
        close(client.sshchan; allow_fail=true)
    end

    # This will throw if the channel's auto-poll failed with an SSH_ERROR.
    wait(client.sshchan)
end

# Struct to represent a client connected to a forwarded port
mutable struct _ForwardingClient
    const id::Int
    verbose::Bool

    sock::TCPSocket
    sshchan::SshChannel
    callbacks::ChannelCallbacks
    client_task::Union{Task, Nothing}

    function _ForwardingClient(forwarder, socket::TCPSocket)
        remotehost = forwarder.remotehost
        remoteport = forwarder.remoteport

        # Open a forwarding channel
        local_ip = string(getaddrinfo(gethostname()))
        sshchan = SshChannel(forwarder._session)
        ret = _session_trywait(forwarder._session) do
            GC.@preserve remotehost local_ip begin
                lib.ssh_channel_open_forward(sshchan,
                                             Base.unsafe_convert(Ptr{Cchar}, remotehost), remoteport,
                                             Base.unsafe_convert(Ptr{Cchar}, local_ip), forwarder.localport)
            end
        end
        if ret != SSH_OK
            throw(LibSSHException("Could not open a forwarding channel: $(get_error(forwarder._session))"))
        end

        callbacks = ChannelCallbacks(nothing;
                                     on_data=_on_client_channel_data,
                                     on_eof=_on_client_channel_eof,
                                     on_close=_on_client_channel_close)
        self = new(forwarder._next_client_id, forwarder.verbose, socket,
                   sshchan, callbacks, nothing)

        # Set callbacks for the channel
        callbacks.userdata = self
        set_channel_callbacks(sshchan, callbacks)

        # Start a listener on the new socket to forward data to the server
        self.client_task = Threads.@spawn try
            _handle_forwarding_client(self)
        catch ex
            @error "Error when handling SSH port forward client $(self.id)!" exception=(ex, catch_backtrace())
        end
        errormonitor(self.client_task)

        return self
    end
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
            # closewrite() can fail with ENOTCONN if the remote end has
            # already disconnected, which is harmless during teardown.
            try
                closewrite(client.sock)
            catch ex
                ex isa Base.IOError || rethrow()
            end
        end
        close(client.sock)
    end

    close(client.sshchan; allow_fail=true)
    wait(client.client_task)
end

"""
$(TYPEDEF)
$(TYPEDFIELDS)

This object manages a direct forwarding channel between `localport` and
`remotehost:remoteport`. Fields beginning with an underscore `_` are private and
should not be used.

!!! warning
    `Forwarder`'s *must* be closed explicitly with
    [`Base.close(::Forwarder)`](@ref). There is no finalizer, so failing to close
    a `Forwarder` will leak resources.
"""
@kwdef mutable struct Forwarder
    remotehost::String
    remoteport::Int
    localinterface::Sockets.IPAddr = Sockets.localhost
    localport::Int = -1

    out::Union{TCPSocket, Nothing} = nothing

    _listen_server::TCPServer = TCPServer()
    _listener_task::Union{Task, Nothing} = nothing
    _clients::Vector{_ForwardingClient} = _ForwardingClient[]
    _next_client_id::Int = 1

    _session::Session
    verbose::Bool
end

"""
$(TYPEDSIGNATURES)

Create a `Forwarder` object that will forward its data to a single
`TCPSocket`. This is useful if there is only one client and binding to a port
available to other processes is not desirable. The socket will be stored in the
`Forwarder.out` property, and it will be closed when the `Forwarder` is closed.

All arguments mean the same as in [`Forwarder(::Session, ::Int, ::String,
::Int)`](@ref).
"""
function Forwarder(session::Session, remotehost::String, remoteport::Int;
                   verbose=false)
    sock1, sock2 = _socketpair()
    self = Forwarder(; remotehost, remoteport, out=sock2, _session=session, verbose)
    push!(self._clients, _ForwardingClient(self, sock1))

    return self
end

"""
$(TYPEDSIGNATURES)

Create a `Forwarder` object to forward data from `localport` to
`remotehost:remoteport`. This will handle an internal [`SshChannel`](@ref)
for forwarding.

# Arguments
- `session`: The session to create a forwarding channel over.
- `localport`: The local port to bind to.
- `remotehost`: The remote host.
- `remoteport`: The remote port to bind to.
- `verbose`: Print logging messages on callbacks etc (not equivalent to
  setting `log_verbosity` on a [`Session`](@ref)).
- `localinterface=IPv4(0)`: The interface to bind `localport` on.
"""
function Forwarder(session::Session, localport::Int, remotehost::String, remoteport::Int;
                   verbose=false, localinterface::Sockets.IPAddr=IPv4(0))
    _listen_server = Sockets.listen(localinterface, localport)

    self = Forwarder(; remotehost, remoteport, localinterface, localport,
                     _listen_server, _session=session, verbose)

    # Start the listener
    self._listener_task = Threads.@spawn try
        _fwd_listen(self)
    catch ex
        @error "Error in listen loop for Forwarder!" exception=(ex, catch_backtrace())
    end
    errormonitor(self._listener_task)

    self
end


function Base.show(io::IO, f::Forwarder)
    if !isopen(f)
        print(io, Forwarder, "([closed])")
    else
        if isnothing(f.out)
            print(io, Forwarder, "($(f.localinterface):$(f.localport) → $(f.remotehost):$(f.remoteport))")
        else
            print(io, Forwarder, "($(f.out) → $(f.remotehost):$(f.remoteport))")
        end
    end
end

"""
$(TYPEDSIGNATURES)

Do-constructor for a `Forwarder`. All arguments are forwarded to the other
constructors.
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
    if !isnothing(forwarder._listener_task)
        wait(forwarder._listener_task)
    end

    # Close existing clients
    for client in forwarder._clients
        close(client)
    end
end

function Base.isopen(forwarder::Forwarder)
    # If we're forwarding to a bound port then check if the TCPServer is
    # running, otherwise check if the single client socket is still open.
    if isnothing(forwarder.out)
        isopen(forwarder._listen_server)
    else
        isopen(forwarder.out)
    end
end

# This function accepts connections on the local port and sets up
# _ForwardingClient's for them.
function _fwd_listen(forwarder::Forwarder)
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

        push!(forwarder._clients, _ForwardingClient(forwarder, sock))
        forwarder._next_client_id += 1
    end
end
