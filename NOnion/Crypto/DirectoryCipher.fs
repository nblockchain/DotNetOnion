namespace NOnion.Crypto

open System.Security.Cryptography

open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Security

module DirectoryCipher =
    let SHA1(bytes: array<byte>) =
        let sha1Engine = SHA1.Create()
        sha1Engine.ComputeHash bytes

    let SHA256(bytes: array<byte>) =
        let sha256Engine = SHA256.Create()
        sha256Engine.ComputeHash bytes

    let DecryptSignature (publicKey: RsaKeyParameters) (data: array<byte>) =
        let cipher = CipherUtilities.GetCipher "RSA/None/PKCS1Padding"
        cipher.Init(false, publicKey)
        cipher.DoFinal data
