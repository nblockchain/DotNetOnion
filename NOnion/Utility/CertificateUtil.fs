// An implementation for https://github.com/torproject/torspec/blob/cb4ae84a20793a00f35a70aad5df47d4e4c7da7c/cert-spec.txt
namespace NOnion.Utility

open System
open System.IO

open Org.BouncyCastle.Crypto.Signers
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Math.EC.Rfc8032

open NOnion

type CertificateExtensionType =
    // https://github.com/torproject/torspec/blob/cb4ae84a20793a00f35a70aad5df47d4e4c7da7c/cert-spec.txt#L175
    | SignedWithEd25519Key = 4uy

type CertificateExtension =
    {
        Type: CertificateExtensionType
        Flags: byte
        Data: array<byte>
    }

    static member Deserialize(reader: BinaryReader) =
        let dataLength = BinaryIO.ReadBigEndianUInt16 reader |> int

        {
            CertificateExtension.Type =
                reader.ReadByte()
                |> LanguagePrimitives.EnumOfValue<byte, CertificateExtensionType>
            Flags = reader.ReadByte()
            Data = reader.ReadBytes dataLength
        }

    member self.ToBytes() =
        Array.concat
            [
                self.Data.Length
                |> uint16
                |> IntegerSerialization.FromUInt16ToBigEndianByteArray
                Array.singleton(byte self.Type)
                Array.singleton self.Flags
                self.Data
            ]

type CertType =
    // https://github.com/torproject/torspec/blob/cb4ae84a20793a00f35a70aad5df47d4e4c7da7c/cert-spec.txt#L134
    | ShortTermDescriptorSigningKeyByBlindedPublicKey = 8uy
    | IntroPointAuthKeySignedByDescriptorSigningKey = 9uy
    | IntroPointEncKeySignedByDescriptorSigningKey = 11uy

type Certificate =
    {
        Version: byte
        Type: CertType
        ExpirationDate: uint
        CertKeyType: byte
        CertifiedKey: array<byte>
        Extensions: List<CertificateExtension>
        Signature: array<byte>
    }

    member self.TryGetSignedWithEd25519Key() =
        self.Extensions
        |> Seq.tryFind(fun ext ->
            ext.Type = CertificateExtensionType.SignedWithEd25519Key
        )
        |> Option.map(fun ext -> ext.Data)

    static member CreateNew
        certType
        (certifiedKey: array<byte>)
        (signingPublicKey: array<byte>)
        (signingPrivateKey: array<byte>)
        (lifetime: TimeSpan)
        =
        let unsignedCertificate =
            {
                Certificate.Version = 1uy
                CertKeyType = 1uy
                Type = certType
                CertifiedKey = certifiedKey
                ExpirationDate =
                    //TODO: TOR uses newerst hour instead of now
                    (DateTimeUtils.GetTimeSpanSinceEpoch DateTime.UtcNow
                     + lifetime)
                        .TotalHours
                    |> uint
                Extensions =
                    List.singleton(
                        {
                            CertificateExtension.Type =
                                CertificateExtensionType.SignedWithEd25519Key
                            Flags = 0uy
                            Data = signingPublicKey
                        }
                    )
                Signature = Array.empty
            }

        let unsignedCertificateBytes = unsignedCertificate.ToBytes true

        let signature =
            if signingPrivateKey.Length = 32 then
                //Standard private key, we can sign with bouncycastle
                let signer = Ed25519Signer()

                signer.Init(
                    true,
                    Ed25519PrivateKeyParameters(signingPrivateKey, 0)
                )

                signer.BlockUpdate(
                    unsignedCertificateBytes,
                    0,
                    unsignedCertificateBytes.Length
                )

                signer.GenerateSignature()
            elif signingPrivateKey.Length = 64 then
                let signature = Array.zeroCreate<byte> 64

                Ed25519.SignByExtendedKey(
                    signingPrivateKey,
                    signingPublicKey,
                    0,
                    unsignedCertificateBytes,
                    0,
                    unsignedCertificateBytes.Length,
                    signature,
                    0
                )

                signature
            else
                failwith
                    "Invalid private key, private key should either be 32 (standard ed25519) or 64 bytes (expanded ed25519 key)"

        { unsignedCertificate with
            Signature = signature
        }


    static member Deserialize(reader: BinaryReader) =
        let rec readExtensions
            (remainingExtsCount: int)
            (state: List<CertificateExtension>)
            =
            if remainingExtsCount = 0 then
                state
            else
                readExtensions
                    (remainingExtsCount - 1)
                    (CertificateExtension.Deserialize reader :: state)

        {
            Version = reader.ReadByte()
            Type =
                reader.ReadByte()
                |> LanguagePrimitives.EnumOfValue<byte, CertType>
            ExpirationDate = BinaryIO.ReadBigEndianUInt32 reader
            CertKeyType = reader.ReadByte()
            CertifiedKey =
                reader.ReadBytes Constants.CertificateCertifiedKeyLength
            Extensions = readExtensions (reader.ReadByte() |> int) List.empty
            Signature = reader.ReadBytes Constants.CertificateSignatureLength
        }

    static member FromBytes(data: array<byte>) =
        use memStream = new MemoryStream(data)
        use reader = new BinaryReader(memStream)
        Certificate.Deserialize reader

    member self.Validate() =
        match self.TryGetSignedWithEd25519Key() with
        | Some signedByKey ->
            let verifier = Ed25519Signer()
            verifier.Init(false, Ed25519PublicKeyParameters(signedByKey, 0))
            let tmpBytes = self.ToBytes true
            verifier.BlockUpdate(tmpBytes, 0, tmpBytes.Length)

            if not(verifier.VerifySignature self.Signature) then
                failwith "Invalid certificate"
        | None -> ()
    //TODO: validate datetime

    member self.ToBytes(ignoreSig: bool) =
        Array.concat
            [
                Array.singleton self.Version
                Array.singleton(self.Type |> byte)
                IntegerSerialization.FromUInt32ToBigEndianByteArray
                    self.ExpirationDate
                Array.singleton self.CertKeyType
                self.CertifiedKey
                self.Extensions.Length |> byte |> Array.singleton
                self.Extensions
                |> Seq.collect(fun ext -> ext.ToBytes())
                |> Seq.toArray
                if ignoreSig then
                    Array.empty
                else
                    self.Signature
            ]
