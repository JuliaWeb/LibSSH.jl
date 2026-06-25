# Represents a keyboard-interactive prompt from a server
struct KbdintPrompt
    msg::String
    display::Bool
end

# A request to be executed on the session's actor task.
# `f` is a zero-argument callable, `result` is a Channel{Any} for returning
# the result (or Nothing for fire-and-forget requests from finalizers).
struct _SessionRequest
    f::Any        # () -> Any
    result::Union{Channel{Any}, Nothing}  # Nothing = fire-and-forget
end

# Reusable fd-readiness poller for a Session: replaces per-iteration
# FileWatching.poll_fd() by keeping one FDWatcher and one periodic Timer
# for the session's lifetime.
#
# A Threads.Condition coordinates a watcher task (blocks in wait(watcher);
# on readability sets ready=true and waits for the actor to clear it before
# rearming — backpressure against level-triggered POLLIN spin), the periodic
# Timer (notifies the cond per tick so SSH_AGAIN writes get retried), and the
# actor (calls _poll_fd, gets :readable / :timeout / :woken / :closed).
# Writability isn't watched (TCP sockets are almost always writable); writes
# are retried on the next tick instead.
#
# The watcher sits on a dup() of the session fd so libssh closing its own
# fd can't pull libuv's poll handle out from under us. See
# _teardown_fd_poller for the close-ordering race that remains.
@kwdef mutable struct _FdPoller
    const dupfd::RawFD
    const watcher::FileWatching.FDWatcher
    const timer::Timer
    const cond::Threads.Condition
    # Set by the watcher on POLLIN, cleared by the actor once it consumes the
    # readiness. Always accessed under `cond`.
    @atomic ready::Bool
    @atomic woken::Bool
    @atomic stop::Bool
    watcher_task::Union{Task, Nothing} = nothing
end

"""
$(TYPEDEF)
$(TYPEDFIELDS)

Represents an SSH session. Note that some properties such as the host and port are
implemented in `getproperty()`/`setproperty!()` by using the internal values of
the `ssh_session`, i.e. they aren't simply fields of the struct. A `Session` may
be owning or non-owning of its internal pointer to a `lib.ssh_session`.

!!! warning
    `Session`'s *must* be closed explicitly with [`Base.close(::Session)`](@ref).
    There is no finalizer, so failing to close a `Session` will leak resources.
"""
mutable struct Session
    ptr::Union{lib.ssh_session, Nothing}
    owning::Bool
    closeables::Vector{Any}
    server_callbacks::Union{ServerCallbacks, Nothing}

    log_verbosity::Int
    ssh_dir::Union{String, Nothing}
    gssapi_server_identity::Union{String, Nothing}
    process_config::Bool

    _lock::ReentrantLock
    _auth_methods::Union{Vector{AuthMethod}, Nothing}
    _attempted_auth_methods::Vector{AuthMethod}
    _require_init_kbdint::Bool

    # Channel for submitting requests to the actor task. The `Nothing` variant
    # is a wake-up sentinel sent by _wake_actor when the actor may be blocked
    # in the idle take!(requests) path (where a cond notify wouldn't reach).
    _requests::Channel{Union{_SessionRequest, Nothing}}
    # Condition for callers to wait() on (SSH_AGAIN waiters)
    _wakeup::CloseableCondition
    # Channels registered for the actor to poll directly (see poll_loop), held
    # as Any because SshChannel is defined later. Guarded by _wakeup's lock.
    _poll_regs::Vector{Any}
    # Lazily-created fd-readiness poller (see _FdPoller). Only the actor task
    # creates it; teardown can come from the actor or disconnect().
    _fd_poller::Union{Nothing, _FdPoller}
    # Tell the actor task when to stop
    @atomic _stop_flag::Bool
    # When set, the actor and fd poller tasks are pinned to this Julia thread
    # so their per-poll notify/wait handshake stays thread-local. nothing
    # leaves them on the regular multithreaded scheduler.
    _pin_tid::Union{Nothing, Int}
    # The actor task owns ALL C libssh calls for this session. Other tasks
    # submit work via _requests. This ensures thread-safety by construction.
    _actor_task::Task

    @doc """
    $(TYPEDSIGNATURES)

    This is only useful if you already have a `ssh_session` (i.e. in a
    server). Do not use it if you want a client, use the host/port constructor.

    # Arguments
    - `ptr`: A pointer to the `lib.ssh_session` to wrap.
    - `log_verbosity=nothing`: Set the log verbosity for the
       session. This argument will be ignored if `own` is `false` to avoid
       accidentally changing the logging level in callbacks when non-owning
       Sessions are created. You can still set the logging level explicitly with
       `session.log_verbosity` if necessary.
    - `own=true`: Whether to take ownership of `ptr`.
    """
    function Session(ptr::lib.ssh_session; log_verbosity=nothing, own::Bool=true,
                     pin_tid::Union{Nothing, Integer}=nothing)
        session = new(ptr, own, [], nothing,
                      -1, nothing, nothing, true,
                      ReentrantLock(), nothing, AuthMethod[], true,
                      Channel{Union{_SessionRequest, Nothing}}(256), CloseableCondition(), Any[], nothing, false,
                      isnothing(pin_tid) ? nothing : Int(pin_tid))

        if own
            # Set to non-blocking mode
            lib.ssh_set_blocking(ptr, 0)

            # Start the actor task — only for owning Sessions.
            # Non-owning Sessions are lightweight wrappers used in callbacks;
            # they must NOT start an actor or make C calls, since the owning
            # Session's actor already owns all C calls for this ssh_session.
            session._actor_task = _spawn_session_task(() -> _actor_loop(session),
                                                      session._pin_tid)
            errormonitor(session._actor_task)

            if !isnothing(log_verbosity)
                session.log_verbosity = log_verbosity
            end
        end

        return session
    end
end

function Base.unsafe_convert(::Type{lib.ssh_session}, session::Session)
    ptr = getfield(session, :ptr)
    if isnothing(ptr)
        throw(ArgumentError("Session is unassigned, cannot get a pointer from it"))
    end

    return ptr
end

Base.unsafe_convert(::Type{Ptr{Cvoid}}, session::Session) = Ptr{Cvoid}(Base.unsafe_convert(lib.ssh_session, session))

function _safe_getproperty(session::Session, name::Symbol)
    try
        getproperty(session, name)
    catch ex
        if ex isa LibSSHException
            "<unset>"
        else
            rethrow()
        end
    end
end

function Base.show(io::IO, session::Session)
    if !isopen(session)
        print(io, Session, "([closed])")
    elseif !session.owning
        # Non-owning sessions can't make C calls (those go through the owning
        # session's actor), so we can't fetch host/user/etc. here.
        print(io, Session, "(non-owning, ptr=$(session.ptr))")
    else
        host = _safe_getproperty(session, :host)
        user = _safe_getproperty(session, :user)

        print(io, Session, "(host=$(host), port=$(session.port), user=$(user), connected=$(isconnected(session)))")
    end
end

Base.lock(session::Session) = lock(session._lock)
Base.unlock(session::Session) = unlock(session._lock)
Base.islocked(session::Session) = islocked(session._lock)
Base.trylock(session::Session) = trylock(session._lock)

"""
    _session_call(session::Session, f) -> Any

Submit a zero-argument callable `f` to the session's actor task for execution
and wait for the result. If the current task IS the actor task (e.g. inside a
callback), `f` is called directly to avoid deadlock.

Throws any exception that `f` throws.
"""
function _session_call(session::Session, f)
    if !session.owning
        throw(ArgumentError("Cannot call _session_call on a non-owning Session. Use the owning Session instead."))
    end
    if current_task() === session._actor_task
        # Already on the actor — direct call (critical for callbacks!)
        return f()
    end

    # Reuse a per-task result channel to avoid allocating a fresh Channel on
    # every call. The channel is never closed; it's only stale if a prior
    # take! was interrupted before reading the actor's put!.
    tls = task_local_storage()
    result_ch = get!(tls, :_libssh_session_call_result_ch) do
        Channel{Any}(1)
    end::Channel{Any}
    if isready(result_ch)
        take!(result_ch)
    end

    try
        put!(session._requests, _SessionRequest(f, result_ch))
    catch ex
        if ex isa InvalidStateException
            throw(LibSSHException("Session is closed"))
        end
        rethrow()
    end
    _wake_actor(session)
    tag, value = take!(result_ch)
    tag === :ok ? value : throw(value)
end

"""
$(TYPEDSIGNATURES)

Constructor for creating a client session. Use this if you want to connect to a
server.

!!! warning
    By default libssh will try to follow the settings in any found SSH config
    files. If a proxyjump is configured for `host` libssh will try to set up the
    proxy itself, which usually does not play well with Julia's event loop. In
    such situations you will probably want to pass `process_config=false` and
    set up the proxyjump explicitly using a [`Forwarder`](@ref).

# Throws
- [`LibSSHException`](@ref): if a session couldn't be created, or there was an
  error initializing the `user` property.

# Arguments
- `host`: The host to connect to.
- `port=22`: The port to connect to.
- `socket=nothing`: Can be an open `TCPSocket` or `RawFD` to connect to
  directly. If this is not `nothing` it will be used instead of `port`. You will
  need to close the socket afterwards, the `Session` will not do it for you.
- `user=nothing`: Set the user to connect as. If unset the current
   username will be used.
- `log_verbosity=nothing`: Set the log verbosity for the session.
- `auto_connect=true`: Whether to automatically call
  [`connect()`](@ref).
- `process_config=true`: Whether to process any found SSH config files.

# Examples

```julia-repl
julia> import LibSSH as ssh
julia> session = ssh.Session("foo.org")
julia> session = ssh.Session(ip"12.34.56.78", 2222)
```
"""
function Session(host::Union{AbstractString, Sockets.IPAddr}, port=22;
                 socket::Union{Sockets.TCPSocket, RawFD, Nothing}=nothing,
                 user=nothing, log_verbosity=nothing, auto_connect=true,
                 process_config=true, pin_tid::Union{Nothing, Integer}=nothing)
    session_ptr = lib.ssh_new()
    if session_ptr == C_NULL
        throw(LibSSHException("Could not initialize Session for host $(host)"))
    end

    host_str = host isa AbstractString ? host : string(host)

    session = Session(session_ptr; log_verbosity, pin_tid)

    # Put this section in a try-catch block so that the session will be free'd
    # if initialization fails for some reason.
    try
        session.host = host_str

        if isnothing(socket)
            session.port = port
        else
            session.fd = socket isa RawFD ? socket : Base._fd(socket)
        end

        if isnothing(user)
            # Explicitly initialize the user, otherwise an error will be thrown when
            # retrieving it. Passing null will set it to the current user (see docs).
            _session_call(session, () -> lib.ssh_options_set(session, SSH_OPTIONS_USER, C_NULL))
        else
            session.user = user
        end

        session.process_config = process_config

        if auto_connect
            connect(session)
        end

        return session
    catch
        close(session)
        rethrow()
    end
end

"""
$(TYPEDSIGNATURES)

Do-constructor for [`Session`](@ref). All arguments are forwarded to the other
constructors.
"""
function Session(f::Function, args...; kwargs...)
    session = Session(args...; kwargs...)
    try
        return f(session)
    finally
        close(session)
    end
end

"""
$(TYPEDSIGNATURES)

Check if the `Session` holds a valid pointer to a `lib.ssh_session`. This will
be `false` if the session has been closed.
"""
Base.isassigned(session::Session) = !isnothing(getfield(session, :ptr))

# Make the Session closed for wait()'ing and wake up any existing waiting
# tasks. This is probably only useful in servers.
function closewait(session::Session)
    # Stop the actor task by setting the flag and closing the request channel
    @atomic session._stop_flag = true
    close(session._requests)

    # Wake up any tasks waiting on the session (e.g. _session_trywait callers)
    # BEFORE waiting for the actor, so those tasks can unblock and exit.
    @lock session._wakeup close(session._wakeup)

    wait(session._actor_task)
end

"""
$(TYPEDSIGNATURES)

Closes a session, which will be unusable afterwards. It's safe to call this
multiple times.

# Throws
- `ArgumentError`: If the session is non-owning. This is not allowed to prevent
  accidental double-frees.
"""
function Base.close(session::Session)
    if !session.owning
        throw(ArgumentError("Calling close() on a non-owning Session is not allowed to avoid accidental double-frees, see the docs for more information."))
    end

    if isopen(session)
        # Disconnect while the actor is still running so C calls go through it
        disconnect(session)

        # Now stop the actor
        closewait(session)

        # Free directly — actor is stopped, no concurrent C calls possible
        lib.ssh_free(session)
        session.ptr = nothing
    end
end

"""
$(TYPEDSIGNATURES)

Check if a session is open.
"""
Base.isopen(session::Session) = isassigned(session) # We currently don't allow closed sessions

"""
$(TYPEDSIGNATURES)

Get the last error set by libssh.

# Throws
- `ArgumentError`: If the session has been closed.

Wrapper around [`lib.ssh_get_error()`](@ref).
"""
function get_error(session::Session)
    if !isassigned(session)
        throw(ArgumentError("Session has been free'd, cannot get its error"))
    end

    return _session_call(session, () -> begin
        ret = lib.ssh_get_error(session)
        unsafe_string(ret)
    end)
end

# Mapping from option name to the corresponding enum and C type
const SESSION_PROPERTY_OPTIONS = Dict(:host => (SSH_OPTIONS_HOST, Cstring),
                                      :port => (SSH_OPTIONS_PORT, Cuint),
                                      :fd => (SSH_OPTIONS_FD, Cint),
                                      :user => (SSH_OPTIONS_USER, Cstring),
                                      :ssh_dir => (SSH_OPTIONS_SSH_DIR, Cstring),
                                      :known_hosts => (SSH_OPTIONS_KNOWNHOSTS, Cstring),
                                      :gssapi_server_identity => (SSH_OPTIONS_GSSAPI_SERVER_IDENTITY, Cstring),
                                      :log_verbosity => (SSH_OPTIONS_LOG_VERBOSITY, Cuint),
                                      :process_config => (SSH_OPTIONS_PROCESS_CONFIG, Bool))
# These properties cannot be retrieved from the libssh API (i.e. with
# ssh_options_get()), so we store them in the Session object instead.
const SAVED_PROPERTIES = (:log_verbosity, :gssapi_server_identity, :ssh_dir, :process_config)

const _SESSION_PROPERTYNAMES = (tuple(keys(SESSION_PROPERTY_OPTIONS)...)..., fieldnames(Session)...)

Base.propertynames(::Session, private::Bool=false) = _SESSION_PROPERTYNAMES

function Base.getproperty(session::Session, name::Symbol)
    # Fast path: direct field access. hasfield is constant-folded for literal
    # symbols, so calls like `session._stop_flag` compile to a plain getfield.
    if hasfield(Session, name)
        return getfield(session, name)
    end

    if name ∉ _SESSION_PROPERTYNAMES
        error("type Session has no field $(name)")
    end

    # Otherwise, we retrieve it from the ssh_session object
    return _session_call(session, () -> begin
        ret = 0
        value = nothing
        is_string = false

        if name === :port
            # The port is a special option with its own function
            port = Ref{Cuint}(0)
            ret = lib.ssh_options_get_port(session, port; throw=false)
            value = UInt(port[])
        elseif name === :fd
            value = RawFD(lib.ssh_get_fd(session))
        else
            # All properties supported by ssh_options_get() are strings, so we know
            # that this option must be a string.
            is_string = true
            option = SESSION_PROPERTY_OPTIONS[name][1]

            out = Ref{Ptr{Cchar}}()
            ret = lib.ssh_options_get(session, option, out; throw=false)
        end

        if ret != 0
            throw(LibSSHException("Error getting $(name) from session: $(ret)"))
        end

        if is_string
            value = unsafe_string(out[])
            lib.ssh_string_free_char(out[])
        end

        value
    end)
end

function Base.setproperty!(session::Session, name::Symbol, value)
    if name ∉ propertynames(session, true)
        error("type Session has no field $(name)")
    end

    if name in (:ptr, :server_callbacks, :_auth_methods, :_attempted_auth_methods,
                :_kbdint_prompts, :_require_init_kbdint, :_actor_task, :_stop_flag,
                :_fd_poller)
        return setfield!(session, name, value)
    end

    # There's some weirdness around saving strings, so we do some special-casing
    # here to handle them.
    option, ctype = SESSION_PROPERTY_OPTIONS[name]
    is_string = ctype == Cstring

    # Always convert string values to String, types like SubString cannot be
    # converted to Cstring.
    ret = if is_string
        value_str = String(value)
        GC.@preserve value_str begin
            cvalue = Base.unsafe_convert(ctype, value_str)
            _session_call(session, () -> lib.ssh_options_set(session, option, Ptr{Cvoid}(cvalue); throw=false))
        end
    else
        GC.@preserve value begin
            cvalue = Base.cconvert(ctype, value)
            _session_call(session, () -> lib.ssh_options_set(session, option, Ref(cvalue); throw=false))
        end
    end

    if ret != 0
        throw(LibSSHException("Error setting Session.$(name) to $(value): $(ret)"))
    end

    # Some properties cannot be retrieved from the libssh API, so we also save
    # them explicitly in the Session.
    if name in SAVED_PROPERTIES
        saved_type = fieldtype(Session, name)
        converted_value = saved_type isa Union ? value : saved_type(value)
        setfield!(session, name, converted_value)
    end

    return value
end

# Helper macro to lock a session and temporarily set it to blocking mode while
# executing some expression.
macro lockandblock(session, expr)
    quote
        @lock $(esc(session)) begin
            lib.ssh_set_blocking($(esc(session)), 1)

            try
                $(esc(expr))
            finally
                lib.ssh_set_blocking($(esc(session)), 0)
            end
        end
    end
end

"""
$(TYPEDSIGNATURES)

Waits for data to be readable/writable on a session.

# Throws
- `InvalidStateException`: If the session is already closed, or is closed while
  waiting.
"""
function Base.wait(session::Session)
    if !isopen(session)
        throw(InvalidStateException("Session is closed, cannot wait() on it", :closed))
    end

    @lock session._wakeup begin
        # Nudge the actor so it cycles through a poll and notifies _wakeup.
        _wake_actor(session)
        wait(session._wakeup)
    end
end

# Process a single request from the actor loop.
# We use invokelatest because the closure may have been created in a newer
# world age than the actor task (e.g. REPL usage, or test code loaded after
# LibSSH).
_process_request(::Nothing) = nothing
function _process_request(req::_SessionRequest)
    if isnothing(req.result)
        # Fire-and-forget: run and discard result/errors
        try
            @invokelatest req.f()
        catch
        end
    else
        try
            value = @invokelatest req.f()
            put!(req.result, (:ok, value))
        catch ex
            put!(req.result, (:err, ex))
        end
    end
end

# External wake-up nudge. The actor has two blocking points and we don't
# know which one it's in, so we nudge both:
#   - cond notify (with `woken`=true): wakes _poll_fd.
#   - nothing sentinel on _requests: wakes the idle take!(requests) branch.
# The redundant signal on the path the actor isn't using is harmless: the
# sentinel becomes a no-op on the next drain; the cond wake just causes one
# extra trip through the poll loop.
function _wake_actor(session::Session)
    p = session._fd_poller
    if !isnothing(p)
        @lock p.cond begin
            @atomic p.woken = true
            notify(p.cond; all=true)
        end
    end
    try
        put!(session._requests, nothing)
    catch
    end
end

# Watcher task: wait for POLLIN, publish ready=true, then block until the
# actor clears it before rearming. The handshake stops level-triggered
# POLLIN from spinning while the actor is still draining.
function _watcher_loop(p::_FdPoller)
    while !(@atomic p.stop)
        try
            wait(p.watcher)
        catch
            # EOFError (watcher closed) or IOError if the dup fd was pulled
            # out from under us. Either way: exit.
            break
        end
        (@atomic p.stop) && break

        @lock p.cond begin
            @atomic p.ready = true
            notify(p.cond; all=true)
            while (@atomic p.ready) && !(@atomic p.stop)
                wait(p.cond)
            end
        end
    end

    # Make sure no one is left blocked on us.
    @lock p.cond notify(p.cond; all=true)
end

# Reusable poll_fd for the session actor. Returns :readable (POLLIN),
# :woken (external nudge), :timeout, or :closed. Single-consumer — only
# the actor task may call this.
function _poll_fd(p::_FdPoller, timeout_s::Real)
    deadline = time() + timeout_s
    @lock p.cond begin
        while true
            (@atomic p.stop) && return :closed
            if (@atomic p.woken)
                @atomic p.woken = false
                return :woken
            end
            if (@atomic p.ready)
                @atomic p.ready = false
                notify(p.cond; all=true)   # release watcher to rearm
                return :readable
            end
            remaining = deadline - time()
            remaining <= 0 && return :timeout
            wait(p.cond)
        end
    end
end

# Pin `task` to Julia thread `tid` (1-based). Used to co-locate the actor
# and its watcher so their per-poll notify/wait stays thread-local.
function pintask!(task::Task, tid::Integer)
    if tid ∉ Threads.threadpooltids(:default) && tid ∉ Threads.threadpooltids(:interactive)
        error("Thread ID '$tid' does not exist in the :default or :interactive threadpool, cannot schedule a task onto it.")
    end

    task.sticky = true
    ret = ccall(:jl_set_task_tid, Cint, (Any, Cint), task, tid - 1)

    if Threads.threadid(task) != tid
        error("jl_set_task_tid() onto Julia thread ID $tid failed!")
    end
end

# Spawn `f` on the regular multithreaded scheduler, or pinned to `tid` when
# pinning is enabled for the session.
function _spawn_session_task(f, tid::Union{Nothing, Int})
    if isnothing(tid)
        return Threads.@spawn f()
    end

    task = Task(f)
    pintask!(task, tid)
    schedule(task)
    return task
end

# Create the session's poller the first time the actor sees a valid fd, and
# keep it for the session's lifetime (the socket fd is stable per session).
# Only ever called on the actor task. Returns nothing if the FDWatcher
# couldn't be created (treated like a closed fd by the caller).
function _ensure_fd_poller(session::Session, fd::RawFD)
    p = session._fd_poller
    isnothing(p) || return p

    # dup() so the watcher's lifetime is decoupled from libssh's (see _FdPoller).
    dupfd = Base.Libc.dup(fd)
    if dupfd == RawFD(-1)
        return nothing
    end

    watcher = try
        FileWatching.FDWatcher(dupfd, true, false)
    catch
        ccall(:close, Cint, (Cint,), dupfd)
        return nothing
    end

    cond = Threads.Condition()
    # Periodic tick: bounded latency for SSH_AGAIN write retries and state
    # re-checks that aren't fd-driven.
    timer = Timer(0.1; interval=0.1) do _
        try
            @lock cond notify(cond; all=true)
        catch
        end
    end

    p = _FdPoller(; dupfd, watcher, timer, cond, ready=false, woken=false, stop=false)
    p.watcher_task = errormonitor(_spawn_session_task(() -> _watcher_loop(p),
                                                      session._pin_tid))
    session._fd_poller = p
    return p
end

# Idempotent, callable from any task; exactly one caller wins via the
# atomic stop flag. The watcher sits on our dup, so ordering vs.
# ssh_disconnect() doesn't matter for correctness.
function _teardown_fd_poller(session::Session)
    p = session._fd_poller
    isnothing(p) && return

    # Claim the teardown exactly once.
    (@atomicswap p.stop = true) && return
    session._fd_poller = nothing

    try
        close(p.timer)
    catch
    end
    try
        close(p.watcher)
    catch
    end
    # close(watcher) only *schedules* uv_close; epoll_ctl(DEL) on dupfd
    # runs at some later libuv loop iteration. Closing dupfd before that
    # flush is unsafe: if its number is reused, libuv removes the wrong fd
    # from epoll; if not, epoll_ctl(DEL) -> EBADF aborts the process. The
    # Timer(0.5) makes it rare but not safe — wall time has no causal link
    # to libuv progress. Proper fix: an fd-owning FDWatcher so libuv closes
    # dupfd itself, but FileWatching doesn't expose that publicly. Each
    # teardown also leaks a Timer/libuv handle.
    dupfd = p.dupfd
    Timer(0.5) do _
        ccall(:close, Cint, (Cint,), dupfd)
    end
    # Unblock the watcher task if it's parked in wait(cond) for ready to clear.
    @lock p.cond notify(p.cond; all=true)

    t = p.watcher_task
    if !isnothing(t) && current_task() !== t
        try
            wait(t)
        catch
        end
    end
end

# The actor loop: owns ALL C libssh calls for this session.
function _actor_loop(session::Session)
    requests = session._requests

    try
        while !(@atomic session._stop_flag) && isopen(session)
            # Drain all pending requests, but re-check stop flag each iteration
            # to avoid an infinite drain loop when a caller immediately resubmits.
            while !(@atomic session._stop_flag) && isready(requests)
                req = try
                    take!(requests)
                catch ex
                    ex isa InvalidStateException && @goto drain_remaining
                    rethrow()
                end
                _process_request(req)
            end

            # Check if anyone is waiting for I/O: either an SSH_AGAIN waiter on
            # _wakeup, or a channel registered for direct polling (poll_loop).
            has_waiters, has_regs = @lock session._wakeup begin
                (!isempty(session._wakeup.cond.waitq), !isempty(session._poll_regs))
            end

            if (has_waiters || has_regs) && isopen(session)
                # Poll the fd for I/O readiness — C calls are safe, we're the actor
                fd = RawFD(lib.ssh_get_fd(session))
                if fd == RawFD(-1)
                    # Session has been disconnected, fd is invalid. Close the
                    # wakeup condition so waiters get an InvalidStateException
                    # rather than a spurious normal wakeup.
                    @lock session._wakeup close(session._wakeup)
                    break
                end

                p = _ensure_fd_poller(session, fd)
                if isnothing(p)
                    # Couldn't watch the fd (closed/invalid)
                    break
                end

                result = _poll_fd(p, 0.1)
                if result === :closed || (@atomic session._stop_flag) || !isopen(session)
                    break
                end

                # :readable / :timeout / :woken — drive libssh and wake
                # SSH_AGAIN waiters. Spurious wakes are harmless.
                _actor_poll_channels(session)
                # Only wake the waiters when I/O could have made progress
                # (:readable) or the retry tick elapsed (:timeout).
                if result !== :woken
                    @lock session._wakeup notify(session._wakeup)
                end
            else
                # No waiters — block until a request arrives
                req = try
                    take!(requests)
                catch ex
                    if ex isa InvalidStateException
                        @goto drain_remaining
                    else
                        rethrow()
                    end
                end
                _process_request(req)
            end
        end
    catch ex
        if !(ex isa InvalidStateException)
            @error "Actor loop crashed" exception=(ex, catch_backtrace())
        end
    end

    @label drain_remaining
    # Tear down the fd poller (safety net for exit paths that don't go through
    # disconnect(), e.g. closewait() or a remote-initiated disconnect).
    _teardown_fd_poller(session)

    # Unblock any poll_loop callers waiting on a registered channel.
    _finish_poll_regs(session)

    # Drain any remaining requests and send error responses so callers
    # waiting on take!(result_ch) don't block forever.
    # Note: we use take!() in a try-catch loop rather than checking isready()
    # first, because there's a race between close() and put!() on the requests
    # channel that can cause isready() to return false even when items exist.
    while true
        req = try
            take!(requests)
        catch
            break
        end
        if req isa _SessionRequest && !isnothing(req.result)
            try
                put!(req.result, (:err, LibSSHException("Session actor has stopped")))
            catch
            end
        end
    end

    return nothing
end

"""
$(TYPEDSIGNATURES)

This will throw an exception if connecting fails. You shouldn't need this unless
you've created a session with `Session(; auto_connect=false)`.

Wrapper around [`lib.ssh_connect()`](@ref).
"""
function connect(session::Session)
    if !isassigned(session)
        throw(ArgumentError("Session has been closed, cannot connect it to a server"))
    elseif isconnected(session)
        return
    end

    while true
        ret = _session_call(session, () -> lib.ssh_connect(session))

        if ret == SSH_AGAIN
            wait(session)
        elseif ret == SSH_OK
            break
        else
            throw(LibSSHException("Error connecting to $(session.host) (port $(session.port)): $(get_error(session))"))
        end
    end
end

"""
$(TYPEDSIGNATURES)

Wrapper around [`lib.ssh_disconnect()`](@ref).

!!! warning
    This will close all channels created from the session.
"""
function disconnect(session::Session)
    if !isopen(session) || !isopen(session._requests)
        return
    end
    # Tear down the poller. The watcher is on our dup, so this no longer has
    # to precede lib.ssh_disconnect(); done early simply to stop polling.
    _teardown_fd_poller(session)

    try
        if isconnected(session)
            # We close all the closeables in reverse order because closing them will
            # delete each object from the vector and we don't want to invalidate any
            # indices while deleting. The channels in particular need to be closed
            # here because lib.ssh_disconnect() will free all of them.
            for i in reverse(eachindex(session.closeables))
                # Note that only owning channels are added to session.closeables, which
                # means that this should never throw because the channel is non-owning
                # (of course it may still throw for other reasons).
                close(session.closeables[i])
            end

            _session_call(session, () -> lib.ssh_disconnect(session))
        end
    catch ex
        # The actor may have been stopped by closewait() on another task
        # (e.g. close(Client) calling closewait before the listener's finally
        # block runs disconnect). In that case _session_call will throw.
        if !(ex isa LibSSHException)
            rethrow()
        end
    end
end

"""
$(TYPEDSIGNATURES)

Wrapper around [`lib.ssh_is_connected()`](@ref).
"""
function isconnected(session::Session)
    isassigned(session) ? _session_call(session, () -> lib.ssh_is_connected(session) == 1) : false
end

"""
$(TYPEDSIGNATURES)

Get the public key from server of a connected session.

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error.

Wrapper around [`lib.ssh_get_server_publickey()`](@ref).
"""
function get_server_publickey(session::Session)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot get the servers public key"))
    end

    return _session_call(session, () -> begin
        key_ref = Ref{lib.ssh_key}()
        ret = lib.ssh_get_server_publickey(session, key_ref)
        if ret != SSH_OK
            throw(LibSSHException("Error when getting servers public key: $(ret)"))
        end
        PKI.SshKey(key_ref[])
    end)
end

"""
$(TYPEDSIGNATURES)

Check if the connected servers public key exists in the SSH known hosts
file.

# Throws
- `ArgumentError`: If the session isn't connected.
- [`HostVerificationException`](@ref): If verification failed and
  `throw` is `true`.

# Arguments
- `throw=true`: Whether to throw a
  [`HostVerificationException`](@ref) if the verification fails, otherwise the
  function will just return the verification status.

Wrapper around [`lib.ssh_session_is_known_server()`](@ref).
"""
function is_known_server(session::Session; throw=true)
    if !isconnected(session)
        Base.throw(ArgumentError("Session is disconnected, cannot check the servers public key"))
    end

    status = KnownHosts(Int(_session_call(session, () -> lib.ssh_session_is_known_server(session))))
    if throw && status != KnownHosts_Ok
        Base.throw(HostVerificationException(status))
    end

    return status
end

"""
$(TYPEDSIGNATURES)

Update the users known hosts file with the sessions server key.

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error.

Wrapper around [`lib.ssh_session_update_known_hosts()`](@ref).
"""
function update_known_hosts(session::Session)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot get the servers public key to update the known hosts file"))
    end

    _session_call(session, () -> begin
        ret = lib.ssh_session_update_known_hosts(session)
        if ret != SSH_OK
            throw(LibSSHException("Could not update the users known hosts file: $(ret)"))
        end
    end)
end

# Helper function to call userauth_kbdint() until we get a non-AuthStatus_Info
# response.
function _try_userauth_kbdint(session::Session, answers, throw)
    # We keep track of when we need to start an keyboard-interactive auth
    # session with the server through the _require_init_kbdint field.
    if session._require_init_kbdint
        userauth_kbdint(session; throw)
    end

    if !isnothing(answers)
        userauth_kbdint_setanswers(session, answers)
    end

    status = userauth_kbdint(session; throw)
    if status == AuthStatus_Info
        prompts = userauth_kbdint_getprompts(session)

        # If the server responds with Info but doesn't send any prompts, then we
        # just keep trying until we get something different. Servers can do that.
        if isempty(prompts)
            return _try_userauth_kbdint(session, nothing, throw)
        end
    end

    # If the auth session is 'over', then set the _require_init_kbdint field so
    # that we know to call userauth_kbdint() again the next time it's tried.
    if status == AuthStatus_Denied
        session._require_init_kbdint = true
    end

    return status
end

function _can_attempt_auth(session::Session, auth_method::AuthMethod)
    auth_method in session._auth_methods && auth_method ∉ session._attempted_auth_methods
end

"""
$(TYPEDSIGNATURES)

This is a helper function that boldly attempts to handle the entire
authentication flow by figuring out which authentication methods are still
available and calling the appropriate functions for you. It may need to be
called multiple times to complete authentication, the idea is that it will only
return when user input is needed (e.g. for a password, or to accept a host key,
etc).

It can return any of:
- A [`KnownHosts`](@ref) to indicate that host verification failed in some
  way. It will not return `KnownHosts_Ok`.
- A [`AuthStatus`](@ref) to indicate that authentication finished in some
  way. The caller doesn't need to do anything else in this case but may retry
  authenticating. It will not return
  `AuthStatus_Info`/`AuthStatus_Again`/`AuthStatus_Partial`.
- A [`AuthMethod`](@ref) to indicate the next method to try. This is only
  returned for auth methods that require user input (i.e. `AuthMethod_Password`
  or `AuthMethod_Interactive`), and the caller must pass the user input next
  time they call `authenticate()`.

!!! warning
    If you're using this function do *not* call any of the other `userauth_*`
    functions, except for [`userauth_kbdint_getprompts()`](@ref) to get the
    server prompts if necessary. `authenticate()` maintains some internal state
    to keep track of where it is in authentication, which can be messed up by
    calling other auth methods yourself.

!!! warning
    `authenticate()` is quite experimental, we suggest testing it with
    [`authenticate_cli()`](@ref) to verify it works on the servers you're
    authenticating to.

# Arguments
- `session`: The [`Session`](@ref) to authenticate.
- `password=nothing`: A password to authenticate with. Pass this if
  `authenticate()` previously returned `AuthMethod_Password`.
- `privkey=nothing`: A `SshKey` to authenticate with. Pass
  this if `authenticate()` previously returned `AuthMethod_PublicKey`.
- `kbdint_answers=nothing`: Answers to keyboard-interactive prompts from the
  server. Use [`userauth_kbdint_getprompts()`](@ref) to get the prompts if
  `authenticate()` returns `AuthMethod_Interactive` and then pass the answers in
  the next call.
- `throw=true`: Whether to throw if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected, or if both `password` and
  `kbdint_answers` are passed.
- `ErrorException`: If there are no more supported authentication methods
  available.
- `LibSSHException`: If there's an internal error and `throw=true`.
"""
function authenticate(session::Session; password=nothing, privkey::Union{PKI.SshKey, Nothing}=nothing, kbdint_answers=nothing, throw=true)
    if !isconnected(session)
        Base.throw(ArgumentError("Session is disconnected, cannot authenticate"))
    elseif !isnothing(password) && !isnothing(kbdint_answers)
        Base.throw(ArgumentError("Only one of `password` or `kbdint_answers` may be passed"))
    end

    # Verify the host key
    host_status = is_known_server(session; throw=false)
    if host_status == KnownHosts_Error
        Base.throw("Error while verifying host key for '$(session.host)': $(host_status)")
    elseif host_status != KnownHosts_Ok
        return host_status
    end

    # Retrieve the supported methods
    session._auth_methods = userauth_list(session;
                                          call_auth_none=isnothing(session._auth_methods))

    # First we check if any of the input arguments have been passed, and we
    # attempt authentication if so.
    if !isnothing(password) || !isnothing(kbdint_answers) || !isnothing(privkey)
        status = if !isnothing(password)
            userauth_password(session, password; throw)
        elseif !isnothing(privkey)
            userauth_publickey(session, privkey; throw)
        else
            _try_userauth_kbdint(session, kbdint_answers, throw)
        end

        # For the sake of consistency we never return AuthStatus_Info to the
        # caller.
        if !isnothing(kbdint_answers) && status == AuthStatus_Info
            status = AuthMethod_Interactive
        end

        return status == AuthStatus_Partial ? authenticate(session; throw) : status
    end

    if isempty(session._auth_methods)
        error("Could not authenticate to the server, no authenication methods left")
    end

    # Otherwise we go through the support auth methods and select one to try.

    # First we try GSSAPI. Handling this one is a little complex because it's
    # allowed to fail if the user hasn't got a ticket for the server.
    if (_can_attempt_auth(session, AuthMethod_GSSAPI_MIC)
        && Gssapi.isavailable()
        && !isnothing(Gssapi.principal_name()))
        status = userauth_gssapi(session; throw)

        if status == AuthStatus_Denied
            push!(session._attempted_auth_methods, AuthMethod_GSSAPI_MIC)

            # If the ticket isn't valid but there are still other methods
            # available, continue trying. Otherwise just return Denied.
            if length(session._auth_methods) > 1
                return authenticate(session; throw)
            else
                return status
            end
        elseif status == AuthStatus_Partial
            # If we're now partially authenticated, then we continue with some
            # other method.
            return authenticate(session; throw)
        else
            return status
        end
    end

    # Then password auth
    if _can_attempt_auth(session, AuthMethod_Password)
        return AuthMethod_Password
    end

    # Then public key auth
    if _can_attempt_auth(session, AuthMethod_PublicKey)
        return AuthMethod_PublicKey
    end

    # Then keyboard-interactive auth
    if _can_attempt_auth(session, AuthMethod_Interactive)
        # Start a keyboard-interactive session if necessary. We call this now so
        # that the caller can call userauth_kbdint_getprompts() immediately.
        if session._require_init_kbdint
            userauth_kbdint(session; throw)
        end

        return AuthMethod_Interactive
    end

    error("The remaining auth methods are not supported: $(session._auth_methods)")
end

function _ask(msg::String)
    print(msg, " [y/n]: ")
    ret = readline()
    return lowercase(ret) == "y"
end

"""
$(TYPEDSIGNATURES)

Meant to mimic authenticating with the `ssh` command by calling
[`authenticate()`](@ref) in a loop while prompting the user if necessary. It's
useful to use this at the REPL to test whether the server can be authenticated
to at all.

# Examples
```julia-repl
julia> session = ssh.Session("test.com"; user="myuser")
LibSSH.Session(host=test.com, port=22, user=myuser, connected=true)

julia> ssh.authenticate_cli(session)
Password:
[ Info: AuthStatus_Info
One-time password:
[ Info: AuthStatus_Success
AuthStatus_Success::AuthStatus = 0
```
"""
function authenticate_cli(session::Session)
    ret = nothing

    while ret != AuthStatus_Success
        ret = authenticate(session)

        if ret == AuthMethod_Password
            buf = Base.getpass("Password")
            println()
            password = read(buf, String)
            Base.shred!(buf)

            ret = authenticate(session; password)
        elseif ret == AuthMethod_Interactive
            prompts = userauth_kbdint_getprompts(session)
            answers = String[]
            for prompt in prompts
                # TODO: use `with_suffix` in Julia 1.12. See
                # https://github.com/JuliaLang/julia/pull/53614.
                buf = Base.getpass(chopsuffix(prompt.msg, ": "))
                println()
                push!(answers, read(buf, String))
                Base.shred!(buf)
            end

            ret = authenticate(session; kbdint_answers=answers)
        elseif ret isa KnownHosts
            server_key = get_server_publickey(session)
            fingerprint = PKI.get_fingerprint_hash(server_key)
            key_type = PKI.key_type(server_key)

            notfound_msg = ret == KnownHosts_NotFound ? " This will create the known_hosts file." : ""
            first_line = if ret == KnownHosts_Changed
                "The server key has changed ($(ret)), this may indicate a MITM attack."
            elseif ret == KnownHosts_Other
                "The server key has changed type ($(ret)) to $(key_type), this may indicate a MITM attack."
            elseif ret == KnownHosts_Unknown || ret == KnownHosts_NotFound
                "Server '$(session.host)' has not been seen before ($(ret))."
            end

            println(first_line)
            println("New $(key_type) key fingerprint: $(fingerprint)")
            if _ask("Do you want to add the key to the known_hosts file and continue?$(notfound_msg)")
                update_known_hosts(session)
            else
                # We can't continue if they don't accept the key
                return ret
            end
        elseif ret == AuthStatus_Success
            # Do nothing
        else
            error("Unsupported return value from authenticate(): $(ret)")
        end

        @info ret
    end

    return ret
end

"""
$(TYPEDSIGNATURES)

Attempt to authenticate to the server without any credentials. This
authentication method is always disabled in practice, but it's still useful to
check which authentication methods the server supports (see
[`userauth_list()`](@ref)).

# Arguments
- `session`: The session to authenticate.
- `throw=true`: Whether to throw if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error, unless `throw=false`.

Wrapper around [`lib.ssh_userauth_none()`](@ref).
"""
function userauth_none(session::Session; throw=true)
    if !isconnected(session)
        Base.throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    while true
        ret = AuthStatus(_session_call(session, () -> lib.ssh_userauth_none(session, C_NULL)))

        if ret == AuthStatus_Again
            wait(session)
        elseif ret == AuthStatus_Error && throw
            Base.throw(LibSSHException("Got AuthStatus_Error (SSH_AUTH_ERROR) when calling userauth_none()"))
        else
            return ret
        end
    end
end

"""
$(TYPEDSIGNATURES)

Get a list of support authentication methods from the server. This will
automatically call [`userauth_none()`](@ref) beforehand if `call_auth_none=true`
(the default).

# Throws
- `ArgumentError`: If the session isn't connected.

Wrapper around [`lib.ssh_userauth_list()`](@ref).
"""
function userauth_list(session::Session; call_auth_none=true)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    # First we have to call ssh_userauth_none() for... some reason, according to
    # the docs.
    if call_auth_none
        userauth_none(session)
    end

    ret = _session_call(session, () -> lib.ssh_userauth_list(session, C_NULL))
    auth_methods = AuthMethod[]
    for method in instances(AuthMethod)
        if (Int(method) & ret) > 0
            push!(auth_methods, method)
        end
    end

    return auth_methods
end

"""
$(TYPEDSIGNATURES)

Authenticate by username and password. The username will be taken from
`session.user`.

# Arguments
- `session`: The session to authenticate.
- `password`: The password to authenticate with.
- `throw=true`: Whether to throw if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error, unless `throw=false`.

Wrapper around [`lib.ssh_userauth_password()`](@ref).
"""
function userauth_password(session::Session, password::String; throw=true)
    if !isconnected(session)
        Base.throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    while true
        ret = GC.@preserve password begin
            password_cstr = Base.unsafe_convert(Ptr{Cchar}, password)
            AuthStatus(_session_call(session, () -> lib.ssh_userauth_password(session, C_NULL, password_cstr)))
        end

        if ret == AuthStatus_Again
            wait(session)
        elseif ret == AuthStatus_Error && throw
            Base.throw(LibSSHException("Got AuthStatus_Error (SSH_AUTH_ERROR) when authenticating"))
        else
            return ret
        end
    end
end

"""
$(TYPEDSIGNATURES)

Authenticate by username and private key. The username will be taken from
`session.user`.

# Arguments
- `session`: The session to authenticate.
- `path`: The private key file path to authenticate with.
- `passphrase=nothing`: An optional passphrase for the private key, if it's encrypted.
- `throw=true`: Whether to throw if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error, unless `throw=false`.

Wrapper around [`lib.ssh_userauth_publickey()`](@ref).
"""
function userauth_publickey(session::Session, path::AbstractString; passphrase=nothing, throw=true)
    privkey = PKI.import_privkey_file(path; passphrase)
    return userauth_publickey(session, privkey; throw)
end

"""
$(TYPEDSIGNATURES)

Authenticate by username and private key. The username will be taken from
`session.user`.

# Arguments
- `session`: The session to authenticate.
- `privkey`: The private key to authenticate with, as a `SshKey` object.
- `throw=true`: Whether to throw if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error, unless `throw=false`.

Wrapper around [`lib.ssh_userauth_publickey()`](@ref).
"""
function userauth_publickey(session::Session, privkey::PKI.SshKey; throw=true)
    if !isconnected(session)
        Base.throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    ret = _session_trywait(session) do
        LibSSH.lib.ssh_userauth_publickey(session, C_NULL, privkey.ptr)
    end
    status = AuthStatus(ret)

    if status == AuthStatus_Error && throw
        Base.throw(LibSSHException("Got AuthStatus_Error (SSH_AUTH_ERROR) when authenticating"))
    end

    return status
end

"""
$(TYPEDSIGNATURES)

Authenticate with GSSAPI. This is not available on all platforms (see
[`Gssapi.isavailable()`](@ref)).

# Arguments
- `session`: The session to authenticate.
- `throw=true`: Whether to throw if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected.
- `ErrorException`: If GSSAPI support isn't available.
- `LibSSHException`: If there was an internal error, unless `throw=false`.

Wrapper around [`lib.ssh_userauth_gssapi()`](@ref).
"""
function userauth_gssapi(session::Session; throw=true)
    if !isconnected(session)
        Base.throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    elseif !Gssapi.isavailable()
        error("GSSAPI support is not available")
    end

    ret = _session_trywait(session) do
        lib.ssh_userauth_gssapi(session)
    end
    status = AuthStatus(ret)

    if status == AuthStatus_Error && throw
        Base.throw(LibSSHException("Got AuthStatus_Error (SSH_AUTH_ERROR) when authenticating"))
    end

    return status
end

"""
$(TYPEDSIGNATURES)

Attempt to authenticate with the keyboard-interactive method.

# Arguments
- `session`: The session to authenticate.
- `throw=true`: Whether to throw if there's an internal error while
  authenticating (`AuthStatus_Error`).

# Throws
- `ArgumentError`: If the session isn't connected.
- `LibSSHException`: If there was an internal error, unless `throw=false`.

Wrapper around [`lib.ssh_userauth_kbdint`](@ref).
"""
function userauth_kbdint(session::Session; throw=true)
    if !isconnected(session)
        Base.throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    ret = _session_trywait(session) do
        lib.ssh_userauth_kbdint(session, C_NULL, C_NULL)
    end
    status = AuthStatus(ret)

    if status == AuthStatus_Error && throw
        Base.throw(LibSSHException("Got AuthStatus_Error (SSH_AUTH_ERROR) when authenticating"))
    end

    session._require_init_kbdint = false

    return status
end

"""
$(TYPEDSIGNATURES)

Returns all the keyboard-interactive prompts from the server. You should have
already called [`userauth_kbdint()`](@ref). The `KbdintPrompt` objects it
returns have `.msg` and `.display` fields that hold the prompt message and
whether to echo the user input (e.g. it will be `false` for a password and other
sensitive input).

This is a combination of [`lib.ssh_userauth_kbdint_getnprompts()`](@ref) and
[`lib.ssh_userauth_kbdint_getprompt()`](@ref). It should be preferred over the
lower-level functions.

# Throws
- `ArgumentError`: If the session isn't connected.
"""
function userauth_kbdint_getprompts(session::Session)
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    return _session_call(session, () -> begin
        prompts = KbdintPrompt[]
        n_prompts = lib.ssh_userauth_kbdint_getnprompts(session)
        for i in 0:n_prompts - 1
            echo_ref = Ref{Cchar}()
            question = lib.ssh_userauth_kbdint_getprompt(session, i, echo_ref)
            push!(prompts, KbdintPrompt(question, Bool(echo_ref[])))
        end
        prompts
    end)
end

"""
$(TYPEDSIGNATURES)

Sets answers for a keyboard-interactive auth session. Uses
[`lib.ssh_userauth_kbdint_setanswer`](@ref) internally.

# Arguments
- `session`: The session to authenticate.
- `answers`: A vector of answers for each prompt sent by the server.

# Throws
- `ArgumentError`: If the session isn't connected, or if the wrong number of
  answers were passed.
- `LibSSHException`: If setting the answers failed.
"""
function userauth_kbdint_setanswers(session::Session, answers::Vector{String})
    if !isconnected(session)
        throw(ArgumentError("Session is disconnected, cannot authenticate until it's connected"))
    end

    _session_call(session, () -> begin
        n_prompts = lib.ssh_userauth_kbdint_getnprompts(session)
        if n_prompts != length(answers)
            throw(ArgumentError("Server sent $(n_prompts) prompts, but was passed $(length(answers)) answers"))
        end

        for (i, answer) in enumerate(answers)
            ret = lib.ssh_userauth_kbdint_setanswer(session, i - 1,
                                                    Base.cconvert(Cstring, answer))
            if ret != SSH_OK
                throw(LibSSHException("Error while setting answer $(i) with ssh_userauth_kbdint_setanswer(): $(ret)"))
            end
        end
    end)
end

#=
Helper function to aid with calling non-blocking functions. It will try calling
`f()` as long as `f()` returns `SSH_AGAIN` or `SSH_AUTH_AGAIN`.
=#
function _session_trywait(f::Function, session::Session)
    ret = SSH_ERROR

    while true
        ret = _session_call(session, f)

        if ret != SSH_AGAIN && ret != lib.SSH_AUTH_AGAIN
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
                    rethrow()
                end
            end
        end
    end

    return ret
end
