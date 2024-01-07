# Low-level bindings

The symbols documented on this page have all been generated automatically, along
with their documentation. Where possible the original documentation from the
libssh headers has been included or a link generated to the upstream
documentation.

Note that some links may not work if the upstream documentation and this page
have been generated against different versions, and some symbols in the
[Other](@ref) section should be elsewhere.

---

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "GLOBAL")
```

## Authentication

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "auth")
```

## Buffers

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "buffer")
```

## Callbacks

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "callbacks")
```

## Channel

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "channel")
```

## Errors

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "error")
```

## Helpers

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "misc")
```

## Logging

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "log")
```

## Message

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "messages")
```

## Polling

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "poll")
```

## Public/private keys

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "pki")
```

## Server

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "server")
```

## Session

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "session")
```

## Strings

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "string")
```

## SCP

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "scp")
```

## SFTP

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "sftp")
```

## Threading

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, "threads")
```

## Other

```@autodocs
Modules = [LibSSH.lib]
Order = [:function, :type, :constant]
Filter = x -> group_filter(x, nothing)
```
