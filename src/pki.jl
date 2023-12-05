module PKI

using DocStringExtensions

import ..lib
import ..LibSSH as ssh

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

@enum KeyCmp begin
    KeyCmp_Public = Int(lib.SSH_KEY_CMP_PUBLIC)
    KeyCmp_Private = Int(lib.SSH_KEY_CMP_PRIVATE)
end

"""
$(TYPEDEF)
$(TYPEDFIELDS)

Use `PKI.generate()` to create a key rather than calling the constructors.

WARNING: adding a SshKey to a Server will cause the key to be free'd when the
Server is closed! Never use a SshKey after its server has been closed, or make
sure it hasn't been closed by checking `isassigned()`.
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

Check if the SshKey holds a valid pointer to a `LibSSH.lib.ssh_key`.
"""
Base.isassigned(key::SshKey) = key.ptr != nothing

"""
$(TYPEDSIGNATURES)

Compare parts of an SSH key. Wrapper around `LibSSH.lib.ssh_key_cmp()`.
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

Wrapper around `LibSSH.lib.ssh_pki_generate()`. Note that `bits=2048` by default.
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

Wrapper around `LibSSH.lib.ssh_key_type()`.
"""
function key_type(key::SshKey)
    if !isassigned(key)
        throw(ArgumentError("SshKey has been free'd, cannot get the key type"))
    end

    ret = lib.ssh_key_type(key.ptr)
    return KeyType(Int(ret))
end

end
