#md # ```@meta
#md # CurrentModule = LibSSH
#md # ```

# # A simple client
#
# First we'll import the LibSSH package:

import LibSSH as ssh

# Sadly there aren't many publicly available SSH servers out there so we'll
# start our own [Demo server](@ref) locally with a Very Secure™ password:

import LibSSH.Demo as demo

demo_server = demo.DemoServer(2222; password="foo", auth_methods=[ssh.AuthMethod_Password])
demo.start(demo_server)

# This is just to have something to play with. Now we can create a
# [`Session`](@ref) to connect to the server:

session = ssh.Session("127.0.0.1", 2222)
@assert ssh.isconnected(session)

# And we have a connection! That means that the key exchange between us and the
# server has finished and we can communicate securely. But we still don't know
# that the server is who it says it is so the next step is authentication *of
# the server*, which means checking its host key. The easiest way to do this is
# by checking the server key against the users known hosts file:

ssh.is_known_server(session; throw_on_failure=false)

# Ok, we got back a `KnownHosts_Unknown` response. That's because the demo
# server automatically creates a dummy key to use, and that definitely won't be
# in the known hosts file. If host verification fails a good client should
# prompt the user with the key fingerprint and ask them what to do. We can get
# the key from the session, hash it, and compute a fingerprint:

import LibSSH.PKI as pki

host_key = ssh.get_server_publickey(session)
sha256_hash = pki.get_publickey_hash(host_key)
fingerprint = pki.get_fingerprint_hash(sha256_hash)

# Or convert it to a hex string with [`get_hexa()`](@ref):

hex = ssh.get_hexa(sha256_hash)

# Since this is a dummy key from the demo server we don't really want to add it
# to our known hosts file, but if this was asked to the user and they said yes,
# it should be added to the known hosts using
# [`update_known_hosts()`](@ref). But since it's a dummy key let's just trust it
# and continue with authenticating ourselves to the server.

# !!! danger
#     Don't skip host verification. It's the only part of the protocol that
#     libssh doesn't handle for you, and security cannot be guaranteed without
#     it.

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

# Now we can disconnect our client session:

close(session)

# And stop the server:

demo.stop(demo_server)
