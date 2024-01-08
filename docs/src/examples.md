```@meta
EditURL = "../../test/examples.jl"
```

```@meta
CurrentModule = LibSSH
```

# A simple client

First we'll import the LibSSH package:

````julia
import LibSSH as ssh
````

Sadly there aren't many publicly available SSH servers out there so we'll
start our own [Demo server](@ref) locally with a simple password:

````julia
import LibSSH.Demo as demo

demo_server = demo.DemoServer(2222; password="foo", auth_methods=[ssh.AuthMethod_Password])
demo.start(demo_server)
````

This is just to have something to play with. Now we can create a
[`Session`](@ref) to connect to the server:

````julia
session = ssh.Session("127.0.0.1", 2222)
ssh.connect(session)
@assert ssh.isconnected(session)
````

And we have a connection! That means that the key exchange between us and the
server has finished and we can communicate securely. Next step is
authentication *of the server*, which means checking its host key.

Since we created the server we already know that it supports password
authentication, but a good client should check anyway:

````julia
ssh.userauth_list(session)
````

````
1-element Vector{LibSSH.AuthMethod}:
 AuthMethod_Password::AuthMethod = 2
````

If we give the wrong password we'll get denied:

````julia
@assert ssh.userauth_password(session, "quux") == ssh.AuthStatus_Denied
````

But the right password should succeed:

````julia
@assert ssh.userauth_password(session, "foo") == ssh.AuthStatus_Success
````

Now we're authenticated to the server and we can actually do something, like
running a command:

````julia
ssh.execute(session, "echo 'Hello world!'")
````

````
(0, "Hello world!\n")
````

What we get back is a tuple of the return code and the output from the
command.

The demo server is very limited and can only do one operation per-instance, so
now we have to disconnect from it:

````julia
close(session)
````

And stop the server:

````julia
demo.stop(demo_server)
````

---

*This page was generated using [Literate.jl](https://github.com/fredrikekre/Literate.jl).*

