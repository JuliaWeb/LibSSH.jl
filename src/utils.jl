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
