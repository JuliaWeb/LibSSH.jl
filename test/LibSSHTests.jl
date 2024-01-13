module LibSSHTests

__revise_mode__ = :eval

import Sockets

import Aqua
import Literate
import CURL_jll: curl
import OpenSSH_jll
import ReTest: @testset, @test, @test_throws, @test_nowarn, @test_logs

import LibSSH
import LibSSH as ssh
import LibSSH.PKI as pki
import LibSSH: lib
import LibSSH.Demo: DemoServer


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

    @testset "Initialization and finalizing" begin
        # We shouldn't be able to create a server without some kind of key
        @test_throws ArgumentError ssh.Bind(2222)
        # We also shouldn't be able to pass multiple keys
        @test_throws ArgumentError ssh.Bind(2222; hostkey=hostkey,
                                            key=pki.generate(pki.KeyType_rsa))

        server = ssh.Bind(2222; hostkey)

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
        @test server.ptr == nothing
    end

    # Helper function to set up an `ssh` command. Slightly ugly workaround to
    # set the necessary environment variables comes from:
    # https://github.com/JuliaLang/julia/issues/39282
    # Also note that we set `-F none` to disabling reading user config files.
    openssh_cmd = OpenSSH_jll.ssh()
    ssh_cmd(cmd::Cmd) = ignorestatus(Cmd(`sshpass -p bar $(openssh_cmd.exec) -F none -o NoHostAuthenticationForLocalhost=yes $cmd`; env=openssh_cmd.env))

    @testset "Password authentication and session channels" begin
        # More complicated test, where we run a command and check the output
        demo_server = DemoServer(2222; password="bar") do
            cmd_out = IOBuffer()
            cmd = ssh_cmd(`-p 2222 foo@localhost whoami`)
            cmd_result = run(pipeline(cmd; stdout=cmd_out))

            @test cmd_result.exitcode == 0
            @test strip(String(take!(cmd_out))) == username()
        end

        logs = demo_server.callback_log

        # Check that the authentication methods were called
        @test logs[:auth_none] == [true]
        @test logs[:auth_password] == [("foo", "bar")]
        @test demo_server.authenticated

        # And a channel was created
        @test !isnothing(demo_server.sshchan)

        # Make sure that it can handle errors too
        DemoServer(2222; password="bar") do
            cmd = ssh_cmd(`-p 2222 foo@localhost exit 42`)
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
        demo_server = DemoServer(2222; password="bar", log_verbosity=ssh.SSH_LOG_NOLOG) do
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
                    curl_process = run(ignorestatus(`$(curl()) localhost:8080`))
                    @test curl_process.exitcode == 0
                end

                # Afterwards we close the client and cleanup
                rm(tmpfile)
                wait(ssh_process)
            end
        end

        @test demo_server.callback_log[:message_request] == [(ssh.RequestType_ChannelOpen, lib.SSH_CHANNEL_DIRECT_TCPIP)]
    end

    @testset "Keyboard-interactive authentication" begin
        demo_server = DemoServer(2222; auth_methods=[ssh.AuthMethod_Interactive]) do
            # Run the script
            script_path = joinpath(@__DIR__, "interactive_ssh.sh")
            proc = run(`expect -f $script_path`; wait=false)
            wait(proc)
        end

        # Check that authentication succeeded
        @test demo_server.authenticated

        # And the command was executed
        @test demo_server.callback_log[:channel_exec_request] == ["whoami"]
    end
end

@testset "Session" begin
    @test ssh.lib_version() isa VersionNumber

    session = ssh.Session("localhost"; log_verbosity=lib.SSH_LOG_NOLOG)

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
    end

    @test !ssh.isconnected(session)

    # Test the finalizer
    finalize(session)
    @test session.ptr == nothing

    @testset "Password authentication" begin
        # Test connecting to a server and doing password authentication
        DemoServer(2222; password="foo") do
            session = ssh.Session(Sockets.localhost, 2222)
            ssh.connect(session)

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
            session = ssh.Session(Sockets.localhost, 2222)
            ssh.connect(session)
            @test ssh.isconnected(session)

            @test ssh.userauth_kbdint(session) == ssh.AuthStatus_Info
            @test ssh.userauth_kbdint_getprompts(session) == [("Password: ", true), ("Token: ", true)]

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
        ssh.connect(session)
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

@testset "SshChannel" begin
    session = ssh.Session("localhost")
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
            @test isempty(session.channels)
        end
    end

    @testset "Executing commands" begin
        # Test executing commands
        demo_server_with_session(2222) do session
            ret, output = ssh.execute(session, "whoami")
            @test ret == 0
            @test strip(output) == username()
        end

        # Check that we read stderr as well as stdout
        demo_server_with_session(2222) do session
            ret, output = ssh.execute(session, "thisdoesntexist")
            @test ret == 127
            @test !isempty(output)
        end
    end

    @testset "Direct port forwarding" begin
        # Test port forwarding
        demo_server_with_session(2222) do session
            forwarder = ssh.Forwarder(session, 8080, "localhost", 9090)
            close(forwarder)
        end

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

@testset "Aqua.jl" begin
    Aqua.test_all(ssh)
end

end
