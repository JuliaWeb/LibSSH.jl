import ReTest: retest
import LibSSH

include("LibSSHTests.jl")

retest(LibSSH, LibSSHTests; verbose=3, stats=false, spin=false)
