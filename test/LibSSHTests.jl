module LibSSHTests

__revise_mode__ = :eval

import Sockets: listen, accept, IPv4, localhost

import Aqua
import Literate
import CURL_jll: curl
import OpenSSH_jll
import ReTest: @testset, @test, @test_throws, @test_nowarn, @test_broken, @test_logs

import LibSSH as ssh
import LibSSH.PKI as pki
import LibSSH: Demo, lib, KbdintPrompt
import LibSSH.Demo: DemoServer


username() = Sys.iswindows() ? ENV["USERNAME"] : ENV["USER"]

const HTTP_200 = "HTTP/1.1 200 OK\r\n\r\n"

# Dummy HTTP server that only responds 200 to requests
function http_server(f::Function, port)
    start_event = Base.Event()
    server = listen(IPv4(0), port)
    t = errormonitor(@async while isopen(server)
                         notify(start_event)
                         local sock
                         try
                             sock = accept(server)
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
                             write(sock, HTTP_200)
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

# Helper function to start a DemoServer and create a session connected to it
function demo_server_with_session(f::Function, port, args...;
                                  timeout=10,
                                  kill_timeout=3,
                                  password="foo",
                                  log_verbosity=lib.SSH_LOG_NOLOG,
                                  kwargs...)
    demo_server = DemoServer(port, args...; password, timeout, kill_timeout, kwargs...) do
        # Create a session
        session = ssh.Session("127.0.0.1", port; log_verbosity)
        @test ssh.isconnected(session)
        @test ssh.userauth_password(session, password) == ssh.AuthStatus_Success

        try
            f(session)
        finally
            ssh.disconnect(session)
            close(session)
        end
    end

    return demo_server
end

@testset "Server" begin
    hostkey = joinpath(@__DIR__, "ed25519_test_key")

    @testset "Initialization and finalizing" begin
        # We shouldn't be able to create a server without some kind of key
        @test_throws ArgumentError ssh.Bind(2222)
        # We also shouldn't be able to pass multiple keys
        @test_throws ArgumentError ssh.Bind(2222; hostkey=hostkey,
                                            key=pki.generate(pki.KeyType_rsa))

        server = ssh.Bind(2222; hostkey)

        # Unsetting a ssh_bind option shouldn't be allowed
        @test_throws ArgumentError server.port = nothing

        @test ssh.get_error(server) == ""

        # Basic listener test
        t = errormonitor(@async ssh.listen(_ -> nothing, server))
        ssh.wait_for_listener(server)

        @test istaskstarted(t)
        close(server)
        wait(t)
        @test istaskdone(t)

        finalize(server)
        @test server.ptr == nothing
    end

    @testset "SessionEvent" begin
        demo_server_with_session(2222; timeout=10) do session
            event = ssh.SessionEvent(session)

            # Smoke test
            show(IOBuffer(), event)

            @test event.ptr isa lib.ssh_event

            close(event)
            @test isnothing(event.ptr)

            event = ssh.SessionEvent(session)
            finalize(event)
            @test isnothing(event.ptr)
        end
    end

    # Helper function to set up an `ssh` command. Slightly ugly workaround to
    # set the necessary environment variables comes from:
    # https://github.com/JuliaLang/julia/issues/39282
    # Also note that we set `-F none` to disabling reading user config files.
    openssh_cmd = OpenSSH_jll.ssh()
    ssh_cmd(cmd::Cmd) = ignorestatus(Cmd(`sshpass -p bar $(openssh_cmd.exec) -F none -o NoHostAuthenticationForLocalhost=yes -p 2222 $cmd`; env=openssh_cmd.env))

    @testset "Command execution" begin
        demo_server = DemoServer(2222; password="bar") do
            # Test exitcodes
            @test run(ssh_cmd(`foo@localhost exit 0`)).exitcode == 0
            @test run(ssh_cmd(`foo@localhost exit 42`)).exitcode == 42

            # Test passing environment variables
            cmd_out = IOBuffer()
            cmd = ssh_cmd(`foo@localhost -o SendEnv=foo echo \$foo`)
            cmd = addenv(cmd, "foo" => "bar")
            cmd_result = run(pipeline(cmd; stdout=cmd_out))

            @test strip(String(take!(cmd_out))) == "bar"
        end
    end

    @testset "Password authentication and session channels" begin
        # More complicated test, where we run a command and check the output
        demo_server = DemoServer(2222; password="bar") do
            cmd_out = IOBuffer()
            cmd = ssh_cmd(`foo@localhost whoami`)
            cmd_result = run(pipeline(cmd; stdout=cmd_out))

            @test cmd_result.exitcode == 0
            @test strip(String(take!(cmd_out))) == username()
        end

        client = demo_server.clients[1]
        logs = client.callback_log

        # Check that the authentication methods were called
        @test logs[:auth_none] == [true]
        @test logs[:auth_password] == [("foo", "bar")]
        @test client.authenticated

        # And a command was executed
        @test typeof.(client.channel_operations) == [Demo.CommandExecutor]

        # Make sure that it can handle errors too
        DemoServer(2222; password="bar") do
            cmd = ssh_cmd(`foo@localhost exit 42`)
            cmd_result = run(pipeline(ignorestatus(cmd)))
            @test cmd_result.exitcode == 42
        end
    end

    @testset "Direct port forwarding" begin
        # Test the dummy HTTP server we'll use later
        http_server(9090) do
            @test run(`$(curl()) localhost:9090`).exitcode == 0
        end

        # Test direct port forwarding
        demo_server = DemoServer(2222; password="bar") do
            mktempdir() do tmpdir
                tmpfile = joinpath(tmpdir, "foo")

                # Start a client and wait for it
                cmd = ssh_cmd(`-L 8080:localhost:9090 foo@localhost "touch $tmpfile; while [ -f $tmpfile ]; do sleep 0.1; done"`)
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
                    curl_process = run(ignorestatus(`$(curl()) localhost:8080`))
                    @test curl_process.exitcode == 0
                end

                # Afterwards we close the client and cleanup
                rm(tmpfile)
                wait(ssh_process)
            end
        end

        client = demo_server.clients[1]
        @test client.callback_log[:message_request] == [(ssh.RequestType_ChannelOpen, lib.SSH_CHANNEL_DIRECT_TCPIP)]
    end

    @testset "Keyboard-interactive authentication" begin
        demo_server = DemoServer(2222; auth_methods=[ssh.AuthMethod_Interactive]) do
            # Run the script
            script_path = joinpath(@__DIR__, "interactive_ssh.sh")
            proc = run(`expect -f $script_path`; wait=false)
            wait(proc)
        end

        client = demo_server.clients[1]

        # Check that authentication succeeded
        @test client.authenticated

        # And the command was executed
        @test client.callback_log[:channel_exec_request] == ["whoami"]
    end

    @testset "Multiple connections" begin
        demo_server = DemoServer(2222; password="bar") do
            run(ssh_cmd(`foo@localhost exit 0`))
            run(ssh_cmd(`foo@localhost exit 0`))
        end
        @test length(demo_server.clients) == 2
    end

    sftp_cmd(cmd::Cmd) = ignorestatus(`sshpass -p bar sftp -F none -o NoHostAuthenticationForLocalhost=yes -P 2222 $cmd`)

    @testset "SFTP" begin
        DemoServer(2222; verbose=false, log_verbosity=ssh.SSH_LOG_NOLOG, password="bar") do
            mktempdir() do tmpdir
                src = joinpath(tmpdir, "foo")
                dest = joinpath(tmpdir, "bar")
                touch(src)

                proc = run(sftp_cmd(`localhost:$(src) $(dest)`))
                @test success(proc)
                @test isfile(dest)
            end
        end
    end

    # Test that the DemoServer cleans up lingering sessions
    server_task = Threads.@spawn DemoServer(2222; timeout=10) do
        session = ssh.Session("127.0.0.1", 2222)
    end
    @test timedwait(() -> istaskdone(server_task), 5) == :ok
end

@testset "Session" begin
    # Connecting to a nonexistent ssh server should fail
    @test_throws ssh.LibSSHException ssh.Session("localhost", 42)

    session = ssh.Session("localhost"; auto_connect=false, log_verbosity=lib.SSH_LOG_NOLOG)
    @test !ssh.isconnected(session)
    @test ssh.get_error(session) == ""

    # Authenticating on an unconnected session should error
    @test_throws ArgumentError ssh.userauth_none(session)

    # We shouldn't be able to close a non-owning session
    non_owning_session = ssh.Session(session.ptr; own=false)
    @test_throws ArgumentError close(non_owning_session)

    @testset "Setting options" begin
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
        session.ssh_dir = "/tmp"
        @test session.ssh_dir == "/tmp"
        session.known_hosts = "/tmp/foo"
        @test session.known_hosts == "/tmp/foo"
        session.gssapi_server_identity = "foo.com"
        @test session.gssapi_server_identity == "foo.com"

        # Test setting an initial user
        session2 = ssh.Session("localhost"; user="foo", auto_connect=false)
        @test session2.user == "foo"
    end

    # Test the finalizer
    finalize(session)
    @test session.ptr == nothing

    @testset "Password authentication" begin
        # Test connecting to a server and doing password authentication
        DemoServer(2222; password="foo") do
            session = ssh.Session(localhost, 2222)

            # The server uses a fake key so it should definitely fail verification
            @test_throws ssh.HostVerificationException ssh.is_known_server(session)

            # We should be able to get the public key
            pubkey = ssh.get_server_publickey(session)
            @test isassigned(pubkey)

            @test ssh.isconnected(session)
            @test ssh.userauth_password(session, "foo") == ssh.AuthStatus_Success

            ssh.disconnect(session)
            close(session)
        end
    end

    @testset "Keyboard-interactive authentication" begin
        DemoServer(2222; auth_methods=[ssh.AuthMethod_Interactive]) do
            session = ssh.Session(localhost, 2222)
            @test ssh.isconnected(session)

            @test ssh.userauth_kbdint(session) == ssh.AuthStatus_Info
            @test ssh.userauth_kbdint_getprompts(session) == [KbdintPrompt("Password: ", true),
                                                              KbdintPrompt("Token: ", true)]

            # This should throw because we're passing the wrong number of answers
            @test_throws ArgumentError ssh.userauth_kbdint_setanswers(session, ["foo"])

            # Test passing incorrect answers
            ssh.userauth_kbdint_setanswers(session, ["foo", "quux"])
            @test ssh.userauth_kbdint(session) == ssh.AuthStatus_Denied

            # And then correct answers
            @test ssh.userauth_kbdint(session) == ssh.AuthStatus_Info
            ssh.userauth_kbdint_setanswers(session, ["foo", "bar"])
            @test ssh.userauth_kbdint(session) == ssh.AuthStatus_Success

            ssh.disconnect(session)
            close(session)
        end
    end

    @testset "GSSAPI authentication" begin
        DemoServer(2222; auth_methods=[ssh.AuthMethod_GSSAPI_MIC]) do
            session = ssh.Session(localhost, 2222)
            @test ssh.isconnected(session)

            # TODO: figure out how to write proper tests for this. It's a little
            # tricky since we'd need to have Kerberos running and configured
            # correctly. In the meantime, this has been tested manually.
            @test_broken ssh.userauth_gssapi(session) == ssh.AuthStatus_Success

            close(session)
        end
    end

    session_helper = (f::Function) -> begin
        session = ssh.Session(localhost, 2222)
        @test ssh.isconnected(session)

        mktemp() do path, io
            session.known_hosts = path
            ssh.update_known_hosts(session)

            try
                f(session)
            finally
                close(session)
            end
        end
    end

    @testset "authenticate()" begin
        # Test with password auth
        DemoServer(2222; auth_methods=[ssh.AuthMethod_Password], password="foo") do
            session = ssh.Session(localhost, 2222)
            @test ssh.isconnected(session)

            mktemp() do path, io
                # Use a new hosts file so we don't mess up the users known_hosts file
                session.known_hosts = path

                # Initially the host will be unknown
                @test ssh.authenticate(session) == ssh.KnownHosts_Unknown
                ssh.update_known_hosts(session)

                # Now there should be an entry in the known_hosts file
                @test startswith(read(io, String), "[127.0.0.1]:2222")

                @test ssh.authenticate(session) == ssh.AuthMethod_Password
                @test ssh.authenticate(session; password="bar") == ssh.AuthStatus_Denied
                @test ssh.authenticate(session; password="foo") == ssh.AuthStatus_Success
            end

            close(session)
        end

        # Test with keyboard-interactive auth
        DemoServer(2222; auth_methods=[ssh.AuthMethod_Interactive]) do
            session_helper() do session
                @test ssh.authenticate(session) == ssh.AuthMethod_Interactive
                @test ssh.authenticate(session; kbdint_answers=["bar", "foo"]) == ssh.AuthStatus_Denied
                @test ssh.authenticate(session; kbdint_answers=["foo", "bar"]) == ssh.AuthStatus_Success
            end
        end

        DemoServer(2222; auth_methods=[ssh.AuthMethod_PublicKey]) do
            session_helper() do session
                # We don't support public key auth yet so this should just throw
                @test_throws ErrorException ssh.authenticate(session)
            end
        end
    end
end

@testset "SshChannel" begin
    session = ssh.Session("localhost"; auto_connect=false)

    # We shouldn't be able to create a channel on an unconnected session
    @test_throws ArgumentError ssh.SshChannel(session)

    @testset "Creating/closing channels" begin
        # Test creating and closing channels
        demo_server_with_session(2222) do session
            # Create a channel
            sshchan = ssh.SshChannel(session)

            # Create a non-owning channel and make sure that we can't close it
            non_owning_sshchan = ssh.SshChannel(sshchan.ptr; own=false)
            @test_throws ArgumentError close(non_owning_sshchan)

            # We shouldn't be able to create a channel from a non-owning session
            non_owning_session = ssh.Session(session.ptr; own=false)
            @test_throws ArgumentError ssh.SshChannel(non_owning_session)

            close(sshchan)
            @test isnothing(sshchan.ptr)
            @test isempty(session.closeables)
        end
    end

    @testset "Command execution" begin
        demo_server_with_session(2222) do session
            # Smoke test
            process = run(`whoami`, session; print_out=false)
            @test success(process)
            @test chomp(String(process.out)) == username()

            # Check that we read stderr as well as stdout
            process = run(ignorestatus(`thisdoesntexist`), session; print_out=false)
            @test process.exitcode == 127
            @test !isempty(String(process.out))

            # Test Base methods
            @test readchomp(`echo foo`, session) == "foo"
            @test success(`whoami`, session)

            # Check that commands with quotes are properly escaped
            @test readchomp(`echo 'foo bar'`, session) == "foo bar"

            # Test setting environment variables
            cmd = setenv(`echo \$foo`, "foo" => "bar")
            @test readchomp(cmd, session) == "bar"
        end
    end

    @testset "Direct port forwarding" begin
        # Smoke test
        demo_server_with_session(2222) do session
            forwarder = ssh.Forwarder(session, 8080, "localhost", 9090)
            close(forwarder)
        end

        # Test forwarding to a port
        demo_server_with_session(2222) do session
            ssh.Forwarder(session, 8080, "localhost", 9090) do forwarder
                http_server(9090) do
                    curl_proc = run(ignorestatus(`$(curl()) localhost:8080`); wait=false)
                    try
                        wait(curl_proc)
                    finally
                        kill(curl_proc)
                    end

                    @test curl_proc.exitcode == 0
                end
            end
        end

        # Test forwarding to a socket
        demo_server_with_session(2222) do session
            ssh.Forwarder(session, "localhost", 9090) do forwarder
                http_server(9090) do
                    socket = forwarder.out
                    write(socket, "foo")
                    @test read(socket, String) == HTTP_200
                end
            end
        end
    end
end

@testset "PKI" begin
    rsa = pki.generate(pki.KeyType_rsa)
    @test pki.key_type(rsa) == pki.KeyType_rsa

    ed = pki.generate(pki.KeyType_ed25519)
    @test !pki.key_cmp(rsa, ed, pki.KeyCmp_Public)
    @test pki.key_cmp(rsa, rsa, pki.KeyCmp_Private)

    # The default hash type should be SHA256 and it should not give any warnings
    sha256_hash = @test_nowarn pki.get_publickey_hash(ed)
    @test length(sha256_hash) == 32

    # But using SHA1 or MD5 should show a warning
    sha1_hash = @test_logs (:warn,) pki.get_publickey_hash(ed, pki.HashType_Sha1)
    @test length(sha1_hash) == 20
    md5_hash = @test_logs (:warn,) pki.get_publickey_hash(ed, pki.HashType_Md5)
    @test length(md5_hash) == 16

    # We should be able to get fingerprints for all hashes without needing to
    # specify the hash type.
    @test startswith(pki.get_fingerprint_hash(sha256_hash), "SHA256:")
    @test startswith(pki.get_fingerprint_hash(sha1_hash), "SHA1:")
    @test startswith(pki.get_fingerprint_hash(md5_hash), "MD5:")

    # But not a fingerprint for a hash with an invalid length
    @test_throws ArgumentError pki.get_fingerprint_hash(rand(UInt8, 33))

    # Test converting the hash buffer to a hex string
    @test replace(ssh.get_hexa(sha256_hash), ":" => "") == bytes2hex(sha256_hash)
end

@testset "GSSAPI" begin
    @test ssh.Gssapi.isavailable() isa Bool

    # Sadly this is quite lightly tested since it's nontrivial to set up a
    # Kerberos instance and acquire a token etc.
    if ssh.Gssapi.isavailable()
        @test ssh.Gssapi.principal_name() isa Union{String, Nothing}
    else
        @test_throws ErrorException ssh.Gssapi.principal_name()
    end
end

@testset "Examples" begin
    mktempdir() do tempdir
        # Test and generate the examples
        Literate.markdown(joinpath(@__DIR__, "../docs/src/examples.jl"),
                          tempdir;
                          execute=true,
                          flavor=Literate.DocumenterFlavor())
    end

    # Dummy test
    @test true
end

@testset "Utility functions" begin
    @test ssh.lib_version() isa VersionNumber
end

@testset "Aqua.jl" begin
    Aqua.test_all(ssh)
end

end
