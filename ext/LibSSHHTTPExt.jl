module LibSSHHTTPExt

import LibSSH as ssh
using HTTP: WebSockets

# Return the single client stream of a Forwarder, or throw if it's a
# listening-port forwarder with no single stream.
function _forwarder_io(forwarder::ssh.Forwarder)
    if isnothing(forwarder.out)
        throw(ArgumentError(
            "This Forwarder has no `.out` stream; WebSocket integration requires a " *
            "single-client Forwarder created with `Forwarder(session, remotehost, remoteport)`."))
    end
    return forwarder.out
end

function WebSockets.open(forwarder::ssh.Forwarder; host::AbstractString=forwarder.remotehost, kwargs...)
    return WebSockets.open(_forwarder_io(forwarder); host, kwargs...)
end

function WebSockets.open(f::Function, forwarder::ssh.Forwarder; host::AbstractString=forwarder.remotehost, kwargs...)
    return WebSockets.open(f, _forwarder_io(forwarder); host, kwargs...)
end

end
