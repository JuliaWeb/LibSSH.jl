```@meta
CurrentModule = LibSSH
```

# Utilities

*The symbols documented on this page are intended to be safe. They may throw
exceptions but they should never cause memory corruptions or segfaults if used
correctly.*

This documents the various other parts of the libssh API that aren't
strictly connected to client or server support.

```@contents
Pages = ["utilities.md"]
Depth = 10
```

---

```@docs
get_hexa
```

## Messages

```@docs
message_type
message_subtype
message_auth_interactive_request
```

## PKI

```@autodocs
Modules = [LibSSH.PKI]
```
