module LibSSHTests

__revise_mode__ = :eval

import ReTest: @testset, @test, @test_throws

import LibSSH as ssh
import LibSSH: lib


function on_auth_password(session, user, password, userdata)::ssh.AuthStatus
    userdata[:user] = user
    userdata[:password] = password

    return ssh.AuthStatus_Success
end

function on_auth_none(session, user, userdata)::ssh.AuthStatus
    userdata[:auth_none] = true
    return ssh.AuthStatus_Denied
end

function on_channel_open(session, userdata)
    sshchan = ssh.SshChannel(session)
    userdata[:channel] = sshchan
    return sshchan
end

@testset "Server" begin
    key_path = joinpath(@__DIR__, "ed25519_test_key")
    server = ssh.Server("0.0.0.0", 2222, key_path)

    # Basic listener test
    t = @async ssh.listen(_ -> nothing, server)
    ssh.wait_for_listener(server)
    @test istaskstarted(t)
    close(server)
    wait(t)
    @test istaskdone(t)

    finalize(server)
    @test server.bind_ptr == nothing

    # More complicated test
    server = ssh.Server("0.0.0.0", 2222, key_path;
                        auth_methods=[ssh.AuthMethod_None, ssh.AuthMethod_Password])
    userdata = Dict{Symbol, Any}(:channel => nothing,
                                 :user => nothing,
                                 :password => nothing,
                                 :auth_none => false)
    callbacks = ssh.Callbacks.ServerCallbacks(userdata;
                                              auth_password_function=on_auth_password,
                                              auth_none_function=on_auth_none,
                                              channel_open_request_session_function=on_channel_open)

    t = @async ssh.listen(server) do session
        ssh.set_server_callbacks(session, callbacks)
        if !ssh.handle_key_exchange(session)
            @error "Key exchange failed"
            return
        end

        event = ssh.SessionEvent(session)
        while isnothing(userdata[:channel])
            ret = ssh.sessionevent_dopoll(event)

            if ret != ssh.SSH_OK
                break
            end
        end

        if !isnothing(userdata[:channel])
            close(userdata[:channel])
        end

        close(event)
    end
    ssh.wait_for_listener(server)

    @test_throws ProcessFailedException run(`sshpass -p bar ssh -v -o NoHostAuthenticationForLocalhost=yes -p 2222 foo@localhost exit`)
    @test userdata[:user] == "foo"
    @test userdata[:password] == "bar"
    @test userdata[:auth_none]
    @test !isnothing(userdata[:channel])

    close(server)
    wait(t)
    finalize(server)
end

@testset "SshChannel" begin
    session = ssh.Session("localhost")
    @test_throws ArgumentError ssh.SshChannel(session)
end

@testset "Session" begin
    session = ssh.Session("localhost")

    # Test initial settings
    user = Sys.iswindows() ? ENV["USERNAME"] : ENV["USER"]
    @test session.user == user
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

    # Test the finalizer
    finalize(session)
    @test session.ptr == nothing
end

end
