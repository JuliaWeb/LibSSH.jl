#md # ```@meta
#md # CurrentModule = LibSSH
#md # ```

# ## Connecting and authenticating
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

ssh.is_known_server(session; throw=false)

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

# Going through all the authentication methods can be quite complicated, in
# practice it may be easier to use [`authenticate()`](@ref) which will handle
# all of that for you.

# ## Running commands
# Now that we're authenticated to the server we can actually do something, like
# running a command (see [Command execution](@ref)):

@assert read(`echo 'Hello world!'`, session, String) == "Hello world!\n"

# ## SFTP
# LibSSH.jl allows reading and writing remote files with the same API as local
# files with `Base`. Lets start by making a temporary directory and creating a
# file in it 'remotely':

tmpdir = mktempdir()
path = joinpath(tmpdir, "foo")

sftp = ssh.SftpSession(session)
file = open(path, sftp; write=true)
write(file, "foo") # this returns the number of bytes written

# We can read the file 'remotely':

open(path, sftp) do readonly_file
    read(readonly_file, String)
end

# And do other IO-related things:

seekstart(file)
position(file)
#-
isreadable(file)
#-
iswritable(file)

# After using it we have to close it explicitly because the finalizer won't do
# it for us (see the [`Base.close(::SftpFile)`](@ref) docstring for details):

close(file)

# ## Disconnecting
# Now we can disconnect our client session:

close(sftp)
close(session)

# And stop the server:

demo.stop(demo_server)

# Note that sometimes the `DemoServer` will display a warning that closing an
# `SshChannel` failed because of `Socket error: disconnected`. That can be
# safely ignored, it just means that the socket was closed on the client side
# before the server could close the `SshChannel`, but the `SshChannel` memory
# will still be freed. It typically happens when doing SFTP operations since the
# [`SftpSession`](@ref) manages its own `lib.ssh_channel`.
