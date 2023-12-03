module LibSSHTests

__revise_mode__ = :eval

import ReTest: @testset, @test, @test_throws

import LibSSH as ssh
import LibSSH: lib


username() = Sys.iswindows() ? ENV["USERNAME"] : ENV["USER"]

function exec_command(command, sshchan)
    @info "starting exec"
    cmd_stdout = IOBuffer()
    cmd_stderr = IOBuffer()

    result = run(pipeline(`sh -c $command`; stdout=cmd_stdout, stderr=cmd_stderr))
    write(sshchan, String(take!(cmd_stdout)))
    write(sshchan, String(take!(cmd_stderr)); stderr=true)
    ssh.channel_request_send_exit_status(sshchan, result.exitcode)
    ssh.channel_send_eof(sshchan)
    close(sshchan)
    @info "stopped exec"
end

function on_auth_password(session, user, password, userdata)::ssh.AuthStatus
    @info "auth password"
    userdata[:user] = user
    userdata[:password] = password

    return ssh.AuthStatus_Success
end

function on_auth_none(session, user, userdata)::ssh.AuthStatus
    @info "auth none"
    userdata[:auth_none] = true
    return ssh.AuthStatus_Denied
end

function on_service_request(session, service, userdata)::Bool
    return true
end

function on_channel_open(session, userdata)
    @info "channel open"
    sshchan = ssh.SshChannel(session)
    userdata[:channel] = sshchan
    return sshchan
end

function on_channel_write_wontblock(session, sshchan, n_bytes, userdata)
    @info "wontblock" n_bytes
    return 0
end

function on_channel_env_request(session, channel, name, value, userdata)
    @info "env request" name value
    return true
end

function on_channel_exec_request(session, channel, command, userdata)
    @info "exec request" command
    Threads.@spawn exec_command(command, channel)
    return true
end

function on_channel_close(session, sshchan, userdata)
    @info "channel close"
    close(sshchan)
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
                                              service_request_function=on_service_request,
                                              channel_open_request_session_function=on_channel_open)
    channel_callbacks = ssh.Callbacks.ChannelCallbacks(userdata;
                                                       channel_close_function=on_channel_close,
                                                       channel_exec_request_function=on_channel_exec_request,
                                                       channel_env_request_function=on_channel_env_request,
                                                       channel_write_wontblock_function=on_channel_write_wontblock)

    t = @async ssh.listen(server) do session
        ssh.set_server_callbacks(session, callbacks)
        if !ssh.handle_key_exchange(session)
            @error "Key exchange failed"
            return
        end

        event = ssh.SshEvent()
        ssh.event_add_session(event, session)
        while isnothing(userdata[:channel])
            ret = ssh.event_dopoll(event, session)

            if ret != ssh.SSH_OK
                break
            end
        end

        if !isnothing(userdata[:channel])
            ssh.Callbacks.set_channel_callbacks(userdata[:channel], channel_callbacks)
            while ssh.event_dopoll(event, session) == ssh.SSH_OK
                continue
            end

            close(userdata[:channel])
        end

        try
            ssh.event_remove_session(event, session)
        catch ex
            # This is commented out because it doesn't seem to be a critical
            # error. Worth investigating in the future though.
            # @error "Error removing session from event" exception=ex
        end

        close(event)
    end
    ssh.wait_for_listener(server)

    cmd_out = IOBuffer()
    cmd = `sshpass -p bar ssh -o NoHostAuthenticationForLocalhost=yes -p 2222 foo@localhost whoami`
    result = run(pipeline(ignorestatus(cmd); stdout=cmd_out))
    close(server)
    wait(t)
    finalize(server)

    @test userdata[:user] == "foo"
    @test userdata[:password] == "bar"
    @test userdata[:auth_none]
    @test !isnothing(userdata[:channel])
    @test result.exitcode == 0
    @test strip(String(take!(cmd_out))) == username()
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

    # Test the finalizer
    finalize(session)
    @test session.ptr == nothing
end

end
