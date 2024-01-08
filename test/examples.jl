#md # ```@meta
#md # CurrentModule = LibSSH
#md # ```

# # A simple client
#
# First we'll import the LibSSH package:

import LibSSH as ssh

# Sadly there aren't many publicly available SSH servers out there so we'll
# start our own [Demo server](@ref) locally with a simple password:

import LibSSH.Demo as demo

demo_server = demo.DemoServer(2222; password="foo", auth_methods=[ssh.AuthMethod_Password])
demo.start(demo_server)

# This is just to have something to play with. Now we can create a
# [`Session`](@ref) to connect to the server:

session = ssh.Session("127.0.0.1", 2222)
ssh.connect(session)
@assert ssh.isconnected(session)

# And we have a connection! That means that the key exchange between us and the
# server has finished and we can communicate securely. Next step is
# authentication *of the server*, which means checking its host key.


# Since we created the server we already know that it supports password
# authentication, but a good client should check anyway:

ssh.userauth_list(session)

# If we give the wrong password we'll get denied:

@assert ssh.userauth_password(session, "quux") == ssh.AuthStatus_Denied

# But the right password should succeed:

@assert ssh.userauth_password(session, "foo") == ssh.AuthStatus_Success

# Now we're authenticated to the server and we can actually do something, like
# running a command:

ssh.execute(session, "echo 'Hello world!'")

# What we get back is a tuple of the return code and the output from the
# command.

# The demo server is very limited and can only do one operation per-instance, so
# now we have to disconnect from it:

close(session)

# And stop the server:

demo.stop(demo_server)
