module LibSSHTests

__revise_mode__ = :eval

import ReTest: @testset, @test, @test_throws

import LibSSH as ssh
import LibSSH.PKI as pki
import LibSSH: lib
import LibSSH.Test as sshtest


username() = Sys.iswindows() ? ENV["USERNAME"] : ENV["USER"]

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
    t = @async ssh.listen(_ -> nothing, server)
    ssh.wait_for_listener(server)

    @test istaskstarted(t)
    close(server)
    wait(t)
    @test istaskdone(t)

    finalize(server)
    @test server.bind_ptr == nothing

    # More complicated test, where we run a command and check the output
    test_server = sshtest.TestServer(2222; password="bar") do
        cmd_out = IOBuffer()
        cmd = `sshpass -p bar ssh -o NoHostAuthenticationForLocalhost=yes -p 2222 foo@localhost whoami`
        cmd_result = run(pipeline(ignorestatus(cmd); stdout=cmd_out))

        @test cmd_result.exitcode == 0
        @test strip(String(take!(cmd_out))) == username()
    end

    logs = test_server.callback_log

    # Check that the authentication methods were called
    @test logs[:auth_none] == [true]
    @test logs[:auth_password] == [("foo", "bar")]

    # And a channel was created
    @test !isnothing(test_server.sshchan)
end

@testset "SshChannel" begin
    session = ssh.Session("localhost")
    @test_throws ArgumentError ssh.SshChannel(session)
end

@testset "Session" begin
    session = ssh.Session("localhost")

    # Test initial settings
    @test session.user == username()
    @test session.port == 22
    @test session.host == "localhost"
    @test session.log_verbosity == lib.SSH_LOG_WARNING

    # Test explicitly setting options with getproperty()/setproperty!()
    session.port = 10
    @test session.port == 10
    session.user = "foo"
    @test session.user == "foo"
    session.host = "quux"
    @test session.host == "quux"
    @test_throws ErrorException session.foo

    @test !ssh.isconnected(session)

    # Test connecting to a server
    session = ssh.Session("127.0.0.1", 2222; log_verbosity=lib.SSH_LOG_NOLOG)
    test_server = sshtest.TestServer(2222; password="foo") do
        ssh.connect(session)

        @test ssh.isconnected(session)
        ssh.userauth_list(session)
        @test ssh.userauth_password(session, "foo") == ssh.AuthStatus_Success

        ssh.disconnect(session)
    end

    # Test the finalizer
    finalize(session)
    @test session.ptr == nothing
end

@testset "PKI" begin
    key = pki.generate(pki.KeyType_rsa)
    @test pki.key_type(key) == pki.KeyType_rsa

    key2 = pki.generate(pki.KeyType_ed25519)
    @test !pki.key_cmp(key, key2, pki.KeyCmp_Public)
    @test pki.key_cmp(key, key, pki.KeyCmp_Private)
end

end
