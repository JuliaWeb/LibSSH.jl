module PKI

using DocStringExtensions

import ..lib
import ..LibSSH as ssh

"""
$(TYPEDEF)

Enum for the types of keys that are supported:
- `KeyType_unknown`
- `KeyType_dss`
- `KeyType_rsa`
- `KeyType_rsa1`
- `KeyType_ecdsa`
- `KeyType_ed25519`
- `KeyType_dss_cert01`
- `KeyType_rsa_cert01`
- `KeyType_ecdsa_p256`
- `KeyType_ecdsa_p384`
- `KeyType_ecdsa_p521`
- `KeyType_ecdsa_p256_cert01`
- `KeyType_ecdsa_p384_cert01`
- `KeyType_ecdsa_p521_cert01`
- `KeyType_ed25519_cert01`
- `KeyType_sk_ecdsa`
- `KeyType_sk_ecdsa_cert01`
- `KeyType_sk_ed25519`
- `KeyType_sk_ed25519_cert01`
"""
@enum KeyType begin
    KeyType_unknown = Int(ssh.SSH_KEYTYPE_UNKNOWN)
    KeyType_dss = Int(ssh.SSH_KEYTYPE_DSS)
    KeyType_rsa = Int(ssh.SSH_KEYTYPE_RSA)
    KeyType_rsa1 = Int(ssh.SSH_KEYTYPE_RSA1)
    KeyType_ecdsa = Int(ssh.SSH_KEYTYPE_ECDSA)
    KeyType_ed25519 = Int(ssh.SSH_KEYTYPE_ED25519)
    KeyType_dss_cert01 = Int(ssh.SSH_KEYTYPE_DSS_CERT01)
    KeyType_rsa_cert01 = Int(ssh.SSH_KEYTYPE_RSA_CERT01)
    KeyType_ecdsa_p256 = Int(ssh.SSH_KEYTYPE_ECDSA_P256)
    KeyType_ecdsa_p384 = Int(ssh.SSH_KEYTYPE_ECDSA_P384)
    KeyType_ecdsa_p521 = Int(ssh.SSH_KEYTYPE_ECDSA_P521)
    KeyType_ecdsa_p256_cert01 = Int(ssh.SSH_KEYTYPE_ECDSA_P256_CERT01)
    KeyType_ecdsa_p384_cert01 = Int(ssh.SSH_KEYTYPE_ECDSA_P384_CERT01)
    KeyType_ecdsa_p521_cert01 = Int(ssh.SSH_KEYTYPE_ECDSA_P521_CERT01)
    KeyType_ed25519_cert01 = Int(ssh.SSH_KEYTYPE_ED25519_CERT01)
    KeyType_sk_ecdsa = Int(ssh.SSH_KEYTYPE_SK_ECDSA)
    KeyType_sk_ecdsa_cert01 = Int(ssh.SSH_KEYTYPE_SK_ECDSA_CERT01)
    KeyType_sk_ed25519 = Int(ssh.SSH_KEYTYPE_SK_ED25519)
    KeyType_sk_ed25519_cert01 = Int(ssh.SSH_KEYTYPE_SK_ED25519_CERT01)
end

"""
$(TYPEDEF)

Enum for ways to compare keys:
- `KeyCmp_Public`
- `KeyCmp_Private`
"""
@enum KeyCmp begin
    KeyCmp_Public = Int(lib.SSH_KEY_CMP_PUBLIC)
    KeyCmp_Private = Int(lib.SSH_KEY_CMP_PRIVATE)
end

"""
$(TYPEDEF)

Enum for possible hash types to use to hash a public key:
- `HashType_Sha1`
- `HashType_Md5`
- `HashType_Sha256`
"""
@enum HashType begin
    HashType_Sha1 = Int(lib.SSH_PUBLICKEY_HASH_SHA1)
    HashType_Md5 = Int(lib.SSH_PUBLICKEY_HASH_MD5)
    HashType_Sha256 = Int(lib.SSH_PUBLICKEY_HASH_SHA256)
end

"""
$(TYPEDEF)
$(TYPEDFIELDS)

Use [`PKI.generate`](@ref) to create a key rather than calling the constructors.

!!! warning
    Adding a `SshKey` to a [`ssh.Bind`](@ref) will cause the key to be free'd
    when the [`ssh.Bind`](@ref) is closed! Never use a `SshKey` after its
    server has been closed, or make sure it hasn't been free'd by checking
    [`isassigned(::SshKey)`](@ref).
"""
mutable struct SshKey
    ptr::Union{lib.ssh_key, Nothing}

    function SshKey()
        ptr = lib.ssh_key_new()
        if ptr == C_NULL
            throw(ssh.LibSSHException("Could not allocate SshKey"))
        end

        return SshKey(ptr)
    end

    function SshKey(ptr::lib.ssh_key)
        if ptr == C_NULL
            throw(ssh.LibSSHException("SshKey pointer is null"))
        end

        self = new(ptr)
        finalizer(_finalizer, self)
    end
end

function _finalizer(key::SshKey)
    if isassigned(key)
        lib.ssh_key_free(key.ptr)
        key.ptr = nothing
    end
end    

"""
$(TYPEDSIGNATURES)

Check if the [`SshKey`](@ref) holds a valid pointer to a `lib.ssh_key`.
"""
Base.isassigned(key::SshKey) = key.ptr != nothing

"""
$(TYPEDSIGNATURES)

Compare parts of an SSH key. Wrapper around [`lib.ssh_key_cmp()`](@ref).
"""
function key_cmp(key1::SshKey, key2::SshKey, part::KeyCmp)
    if !isassigned(key1) || !isassigned(key2)
        throw(ArgumentError("SshKey has been free'd, cannot compare"))
    end

    ret = lib.ssh_key_cmp(key1.ptr, key2.ptr, lib.ssh_keycmp_e(Int(part)))
    return ret == 0
end

"""
$(TYPEDSIGNATURES)

Wrapper around [`lib.ssh_pki_generate()`](@ref). Note that `bits=2048` by default.
"""
function generate(ktype::KeyType; bits::Int=2048)
    ptr_ref = Ref{lib.ssh_key}()
    ret = lib.ssh_pki_generate(lib.ssh_keytypes_e(Int(ktype)), Cint(bits), ptr_ref)
    if ret != ssh.SSH_OK
        throw(ssh.LibSSHException("Error creating cryptographic key: $(ret)"))
    end

    return SshKey(ptr_ref[])
end

"""
$(TYPEDSIGNATURES)

Wrapper around [`lib.ssh_key_type()`](@ref).
"""
function key_type(key::SshKey)
    if !isassigned(key)
        throw(ArgumentError("SshKey has been free'd, cannot get the key type"))
    end

    ret = lib.ssh_key_type(key.ptr)
    return KeyType(Int(ret))
end

"""
$(TYPEDSIGNATURES)

Get the hash of the public key of a [`SshKey`](@ref) (SHA256 by default).

Wrapper around [`lib.ssh_get_publickey_hash()`](@ref).
"""
function get_publickey_hash(key::SshKey, hash_type::HashType=HashType_Sha256)
    if !isassigned(key)
        throw(ArgumentError("SshKey has been free'd, can't get its public key has"))
    end

    if hash_type == HashType_Md5 || hash_type == HashType_Sha1
        @warn "$(hash_type) is being used to compute public key hash, this is not secure"
    end

    # Compute the hash
    hash_arr = Ref{Ptr{Cuchar}}()
    hash_len = Ref{Csize_t}()
    ret = lib.ssh_get_publickey_hash(key.ptr, lib.ssh_publickey_hash_type(Int(hash_type)),
                                     hash_arr, hash_len)
    if ret != lib.SSH_OK
        throw(LibSSHException("Computing the SshKey public key hash failed: $(ret)"))
    end

    # Extract the hash into a Julia-owned array
    non_owning_hash = unsafe_wrap(Array, Ptr{UInt8}(hash_arr[]), hash_len[])
    hash_buffer = copy(non_owning_hash)
    lib.ssh_clean_pubkey_hash(hash_arr)
    non_owning_hash = nothing

    return hash_buffer
end

"""
$(TYPEDSIGNATURES)

Get a fingerprint of a public key from a hash. This will automatically guess the
kind of hash that was used from the length of `hash_buffer`.

Wrapper around [`lib.ssh_get_fingerprint_hash()`](@ref).

## Examples

```julia-repl
julia> import LibSSH.PKI as pki
julia> key = pki.generate(pki.KeyType_ed25519)
julia> sha256_hash = pki.get_publickey_hash(key)
julia> pki.get_fingerprint_hash(sha256_hash)
"SHA256:5muLWD4Cl6FYh5ZRr/DYKvmb5r+kJUZQXLuc6ocVRH0"
```
"""
function get_fingerprint_hash(hash_buffer::Vector{UInt8})
    hash_len = length(hash_buffer)
    hash_type = if hash_len == 32
        HashType_Sha256
    elseif hash_len == 20
        HashType_Sha1
    elseif hash_len == 16
        HashType_Md5
    else
        throw(ArgumentError("Hash buffer length is unsupported, check if the right array was passed"))
    end

    ret = lib.ssh_get_fingerprint_hash(lib.ssh_publickey_hash_type(Int(hash_type)),
                                       Ptr{Cuchar}(pointer(hash_buffer)), length(hash_buffer))
    if ret == C_NULL
        throw(LibSSHException("Could not get fingerprint from $(hash_type) hash"))
    end

    fingerprint = unsafe_string(ret)
    lib.ssh_string_free_char(ret)

    return fingerprint
end

end
