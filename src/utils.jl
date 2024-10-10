import Sockets

# High-level, portable implementation of socketpair(2)
function _socketpair()
    port, server = Sockets.listenany(Sockets.localhost, 2048)
    acceptor = Threads.@spawn Sockets.accept(server)

    sock1 = Sockets.connect(Sockets.localhost, port)
    sock2 = fetch(acceptor)

    close(server)

    return sock1, sock2
end


# Helper type to allow closing a Threads.Condition
mutable struct CloseableCondition
    @atomic closed::Bool
    cond::Threads.Condition

    CloseableCondition() = new(false, Threads.Condition())
end

function Base.wait(cond::CloseableCondition)
    if @atomic cond.closed
        throw(InvalidStateException("Condition has been closed", :closed))
    end

    wait(cond.cond)
end

function Base.close(cond::CloseableCondition)
    @atomic cond.closed = true
    notify(cond, InvalidStateException("Condition is closed", :closed); error=true)
    return nothing
end

Base.notify(cond::CloseableCondition, args...; kwargs...) = notify(cond.cond, args...; kwargs...)
Base.lock(cond::CloseableCondition) = lock(cond.cond)
Base.unlock(cond::CloseableCondition) = unlock(cond.cond)
