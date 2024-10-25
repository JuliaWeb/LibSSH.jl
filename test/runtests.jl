import ReTest: retest
import LibSSH

include("LibSSHTests.jl")

retest(LibSSH, LibSSHTests; stats=true)
