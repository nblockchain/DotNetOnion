namespace NOnion.TorHandshakes

open System.Security.Cryptography

open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Security
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Agreement

open NOnion
open NOnion.Crypto.Kdf

type NTorHandshake =
    private
        {
            RandomClientPrivateKey: X25519PrivateKeyParameters
            RandomClientPublicKey: X25519PublicKeyParameters
            IdentityDigest: array<byte>
            NTorOnionKey: X25519PublicKeyParameters
        }


    static member Create
        (identityDigest: array<byte>)
        (nTorOnionKey: array<byte>)
        =

        let privateKey, publicKey =
            let keyPair =
                let kpGen = X25519KeyPairGenerator()
                let random = SecureRandom()
                kpGen.Init(X25519KeyGenerationParameters random)
                kpGen.GenerateKeyPair()

            keyPair.Private :?> X25519PrivateKeyParameters,
            keyPair.Public :?> X25519PublicKeyParameters

        {
            IdentityDigest = identityDigest
            NTorOnionKey = X25519PublicKeyParameters(nTorOnionKey, 0)
            RandomClientPrivateKey = privateKey
            RandomClientPublicKey = publicKey
        }

    interface IHandshake with
        member self.GenerateClientMaterial() =
            Array.concat
                [
                    self.IdentityDigest
                    self.NTorOnionKey.GetEncoded()
                    self.RandomClientPublicKey.GetEncoded()
                ]

        member self.GenerateKdfResult serverSideData =
            let randomServerPublicKey =
                X25519PublicKeyParameters(serverSideData.ServerHandshake, 0)

            let keyAgreement = X25519Agreement()
            keyAgreement.Init self.RandomClientPrivateKey

            let sharedSecretWithY, sharedSecretWithB =
                Array.zeroCreate keyAgreement.AgreementSize,
                Array.zeroCreate keyAgreement.AgreementSize

            keyAgreement.CalculateAgreement(
                randomServerPublicKey,
                sharedSecretWithY,
                0
            )

            keyAgreement.CalculateAgreement(
                self.NTorOnionKey,
                sharedSecretWithB,
                0
            )

            let secretInput =
                Array.concat
                    [
                        sharedSecretWithY
                        sharedSecretWithB
                        self.IdentityDigest
                        self.NTorOnionKey.GetEncoded()
                        self.RandomClientPublicKey.GetEncoded()
                        randomServerPublicKey.GetEncoded()
                        Constants.NTorProtoId
                    ]

            let calculateHmacSha256 (data: array<byte>) (key: array<byte>) =
                use hmacSha256 = new HMACSHA256(key)

                hmacSha256.ComputeHash data

            let verify = calculateHmacSha256 secretInput Constants.NTorTVerify

            let authInput =
                Array.concat
                    [
                        verify
                        self.IdentityDigest
                        self.NTorOnionKey.GetEncoded()
                        randomServerPublicKey.GetEncoded()
                        self.RandomClientPublicKey.GetEncoded()
                        Constants.NTorAuthInputSuffix
                    ]

            let auth = calculateHmacSha256 authInput Constants.NTorTMac

            if auth <> serverSideData.DerivativeKey then
                raise <| HandshakeFailedException()
            else
                Kdf.ComputeRfc5869Kdf secretInput
