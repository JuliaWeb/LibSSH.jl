module LibSSHTests

__revise_mode__ = :eval

import ReTest: @testset, @test, @test_throws

import LibSSH as ssh
import LibSSH: lib


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
