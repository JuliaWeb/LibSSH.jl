module LibSSHTests

__revise_mode__ = :eval

import Sockets

import ReTest: @testset, @test, @test_throws

import LibSSH as ssh
import LibSSH.PKI as pki
import LibSSH: lib
import LibSSH.Test as sshtest


username() = Sys.iswindows() ? ENV["USERNAME"] : ENV["USER"]

# Dummy HTTP server that only responds 200 to requests
function http_server(f::Function, port)
    start_event = Base.Event()
    server = Sockets.listen(Sockets.IPv4(0), port)
    t = errormonitor(@async while isopen(server)
                         notify(start_event)
                         local sock
                         try
                             sock = Sockets.accept(server)
                         catch ex
                             if ex isa Base.IOError
                                 break
                             else
                                 rethrow()
                             end
                         end

                         # Wait for any request, doesn't matter what
                         data = readavailable(sock)
                         if !isempty(data)
                             write(sock, "HTTP/1.1 200 OK\r\n\r\n")
                         end

                         closewrite(sock)
                         close(sock)
                     end)

    wait(start_event)
    try
        f()
    finally
        close(server)
        wait(t)
    end
end

@testset "Server" begin
    hostkey = joinpath(@__DIR__, "ed25519_test_key")

    # We shouldn't be able to create a server without some kind of key
    @test_throws ArgumentError ssh.Server(2222)
    # We also shouldn't be able to pass multiple keys
    @test_throws ArgumentError ssh.Server(2222; hostkey=hostkey,
                                          key=pki.generate(pki.KeyType_rsa))

    server = ssh.Server(2222; hostkey)

    # Unsetting a ssh_bind option shouldn't be allowed
    @test_throws ArgumentError server.port = nothing

    # Basic listener test
    t = errormonitor(@async ssh.listen(_ -> nothing, server))
    ssh.wait_for_listener(server)

    @test istaskstarted(t)
    close(server)
    wait(t)
    @test istaskdone(t)

    finalize(server)
    @test server.bind_ptr == nothing

    ssh_cmd(cmd::Cmd) = ignorestatus(`sshpass -p bar ssh -o NoHostAuthenticationForLocalhost=yes $cmd`)

    # More complicated test, where we run a command and check the output
    test_server = sshtest.TestServer(2222; password="bar") do
        cmd_out = IOBuffer()
        cmd = ssh_cmd(`-p 2222 foo@localhost whoami`)
        cmd_result = run(pipeline(cmd; stdout=cmd_out))

        @test cmd_result.exitcode == 0
        @test strip(String(take!(cmd_out))) == username()
    end

    logs = test_server.callback_log

    # Check that the authentication methods were called
    @test logs[:auth_none] == [true]
    @test logs[:auth_password] == [("foo", "bar")]

    # And a channel was created
    @test !isnothing(test_server.sshchan)

    # Make sure that it can handle errors too
    test_server = sshtest.TestServer(2222; password="bar") do
        cmd = ssh_cmd(`-p 2222 foo@localhost exit 42`)
        cmd_result = run(pipeline(ignorestatus(cmd)))
        @test cmd_result.exitcode == 42
    end

    # Test the dummy HTTP server we'll use later
    http_server(9090) do
        @test run(`curl localhost:9090`).exitcode == 0
    end

    # Test direct port forwarding. First we start a dummy server that returns a
    # known value, then we start the test server and a curl client to make a
    # request.
    test_server = sshtest.TestServer(2222; password="bar", log_verbosity=ssh.SSH_LOG_NOLOG) do
        mktempdir() do tmpdir
            tmpfile = joinpath(tmpdir, "foo")

            # Start a client and wait for it
            cmd = ssh_cmd(`-p 2222 -L 8080:localhost:9090 foo@localhost "touch $tmpfile; while [ -f $tmpfile ]; do sleep 0.1; done"`)
            ssh_process = run(cmd; wait=false)
            if timedwait(() -> isfile(tmpfile), 5) == :timed_out
                error("Timeout waiting for sentinel file $tmpfile to be created")
            end

            # At this point the client will be listening on port 8080, so we make a
            # request to trigger a forward request to the server. Note that the
            # client only requests a port forward when it accepts a connection
            # on the listening port, so we only need the HTTP server running
            # while we're making the request.
            http_server(9090) do
                curl_process = run(ignorestatus(`curl localhost:8080`))
                @test curl_process.exitcode == 0
            end

            # Afterwards we kill the client and cleanup
            kill(ssh_process, Base.SIGINT)
        end
    end

    @test test_server.callback_log[:message_request] == [(ssh.RequestType_ChannelOpen, lib.SSH_CHANNEL_DIRECT_TCPIP)]
end

@testset "Session" begin
    session = ssh.Session("localhost"; log_verbosity=lib.SSH_LOG_NOLOG)

    # Test initial settings
    @test session.user == username()
    @test session.port == 22
    @test session.host == "localhost"
    @test session.log_verbosity == lib.SSH_LOG_NOLOG

    # Test explicitly setting options with getproperty()/setproperty!()
    session.port = 10
    @test session.port == 10
    session.user = "foo"
    @test session.user == "foo"
    session.host = "quux"
    @test session.host == "quux"
    @test_throws ErrorException session.foo

    @test !ssh.isconnected(session)

    # Test the finalizer
    finalize(session)
    @test session.ptr == nothing

    # Test connecting to a server and doing password authentication
    test_server = sshtest.TestServer(2222; password="foo") do
        session = ssh.Session("127.0.0.1", 2222; log_verbosity=lib.SSH_LOG_NOLOG)
        ssh.connect(session)

        @test ssh.isconnected(session)
        ssh.userauth_list(session)
        @test ssh.userauth_password(session, "foo") == ssh.AuthStatus_Success

        ssh.disconnect(session)
        close(session)
    end
end

# Helper function to start a TestServer and create a session connected to
# it. Also supports timeouts.
function test_server_with_session(f::Function, port, args...;
                                  timeout=10,
                                  kill_grace_period=3,
                                  password="foo",
                                  log_verbosity=lib.SSH_LOG_NOLOG,
                                  kwargs...)
    test_server = sshtest.TestServer(port, args...; password, kwargs...) do
        # Create a session
        session = ssh.Session("127.0.0.1", port; log_verbosity)
        ssh.connect(session)
        @test ssh.isconnected(session)
        @test ssh.userauth_password(session, password) == ssh.AuthStatus_Success

        # Create a timer and start the function
        timer = Timer(timeout)
        still_running = true
        t = Threads.@spawn try
            f(session)
        finally
            still_running = false
            close(timer)
        end

        # Wait for a timeout or the function to finish
        try
            wait(timer)
        catch
            # An exception means that the function finished in time and closed
            # the timer early.
        end

        ssh.disconnect(session)
        close(session)

        # If the function is still running, we attempt to kill it explicitly
        kill_failed = nothing
        if still_running
            @async Base.throwto(t, InterruptException())
            result = timedwait(() -> istaskdone(t), kill_grace_period)
            kill_failed = result == :timed_out
        end

        # If there was a timeout we throw an exception, otherwise we wait() on
        # the task, which will cause any exeption thrown by f() to bubble up.
        if !isnothing(kill_failed)
            kill_failed_msg = kill_failed ? " (failed to kill function, it's still running)" : ""
            error("TestServer function timed out after $(timeout)s" * kill_failed_msg)
        else
            wait(t)
        end
    end

    return test_server
end

@testset "SshChannel" begin
    session = ssh.Session("localhost")
    @test_throws ArgumentError ssh.SshChannel(session)

    # Test creating and closing channels
    test_server_with_session(2222) do session
        # Create a channel
        sshchan = ssh.SshChannel(session)

        # Create a non-owning channel and make sure that we can't close it
        non_owning_sshchan = ssh.SshChannel(sshchan.ptr; own=false)
        @test_throws ArgumentError close(non_owning_sshchan)

        # Set the session pointer to nothing to mock being closed
        session_ptr = sshchan.session.ptr
        sshchan.session.ptr = nothing
        # Test that closing a channel before its session throws an exception
        @test_throws ErrorException close(sshchan)
        # Restore the session pointer
        sshchan.session.ptr = session_ptr

        close(sshchan)
        @test isnothing(sshchan.ptr)
    end

    # Test executing commands
    test_server_with_session(2222) do session
        ret, output = ssh.execute(session, "whoami")
        @test ret == 0
        @test strip(output) == username()
    end

    # Check that we read stderr as well as stdout
    test_server_with_session(2222) do session
        ret, output = ssh.execute(session, "thisdoesntexist")
        @test ret == 127
        @test !isempty(output)
    end
end

@testset "PKI" begin
    key = pki.generate(pki.KeyType_rsa)
    @test pki.key_type(key) == pki.KeyType_rsa

    key2 = pki.generate(pki.KeyType_ed25519)
    @test !pki.key_cmp(key, key2, pki.KeyCmp_Public)
    @test pki.key_cmp(key, key, pki.KeyCmp_Private)
end

end
