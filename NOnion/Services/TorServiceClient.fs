namespace NOnion.Services

open System
open System.IO
open System.Security.Cryptography
open System.Text
open System.Linq

open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Security

open NOnion
open NOnion.Cells.Relay
open NOnion.Crypto
open NOnion.Utility
open NOnion.Directory
open NOnion.Http
open NOnion.Network

type TorServiceClient =
    private
        {
            RendezvousGuard: TorGuard
            RendezvousCircuit: TorCircuit
            Stream: TorStream
        }

    member self.GetStream() =
        self.Stream

    static member ConnectAsync (directory: TorDirectory) (url: string) =
        TorServiceClient.Connect directory url |> Async.StartAsTask

    static member Connect (directory: TorDirectory) (url: string) =
        async {
            let publicKey, port = HiddenServicesUtility.DecodeOnionUrl url

            let getIntroductionPointInfo() =
                async {
                    let! networkStatus = directory.AsyncGetLiveNetworkStatus()

                    let periodNum, periodLength = networkStatus.GetTimePeriod()
                    let srv = networkStatus.GetCurrentSRVForClient()

                    let blindedPublicKey =
                        HiddenServicesCipher.BuildBlindedPublicKey
                            (periodNum, periodLength)
                            publicKey

                    let! responsibleDirs =
                        directory.AsyncGetResponsibleHiddenServiceDirectories
                            blindedPublicKey
                            srv
                            periodNum
                            periodLength
                            Constants.HiddenServices.Hashring.SpreadFetch

                    let rec downloadDescriptor(responsibleDirs: List<string>) =
                        async {
                            match responsibleDirs with
                            | [] ->
                                return
                                    raise <| DescriptorDownloadFailedException()
                            | hsDirectory :: tail ->
                                try
                                    let! guardEndPoint, randomGuardNode =
                                        directory.AsyncGetRouter
                                            RouterType.Guard

                                    let! _, randomMiddleNode =
                                        directory.AsyncGetRouter
                                            RouterType.Normal

                                    let! hsDirectoryNode =
                                        directory.AsyncGetCircuitNodeDetailByIdentity
                                            hsDirectory

                                    use! guardNode =
                                        TorGuard.AsyncNewClientWithIdentity
                                            guardEndPoint
                                            (randomGuardNode.GetIdentityKey()
                                             |> Some)

                                    let circuit = TorCircuit guardNode

                                    do!
                                        circuit.AsyncCreate randomGuardNode
                                        |> Async.Ignore

                                    do!
                                        circuit.AsyncExtend randomMiddleNode
                                        |> Async.Ignore

                                    try
                                        do!
                                            circuit.AsyncExtend hsDirectoryNode
                                            |> Async.Ignore

                                        use dirStream = new TorStream(circuit)

                                        do!
                                            dirStream.AsyncConnectToDirectory()
                                            |> Async.Ignore

                                        let! documentInString =
                                            TorHttpClient(
                                                dirStream,
                                                Constants.DefaultHttpHost
                                            )
                                                .AsyncGetAsString
                                                (sprintf
                                                    "/tor/hs/%i/%s"
                                                    Constants.HiddenServices.Version
                                                    ((Convert.ToBase64String
                                                        blindedPublicKey)))
                                                false

                                        return
                                            HiddenServiceFirstLayerDescriptorDocument.Parse
                                                documentInString
                                    with
                                    | :? NOnionException ->
                                        return! downloadDescriptor tail

                                with
                                | :? NOnionException ->
                                        // Using micro descriptors means we might use servers that are hibernating or etc
                                        // so we need to be able to try multiple servers to receive the descriptor.
                                    return! downloadDescriptor responsibleDirs
                        }

                    let! firstLayerDescriptorDocument =
                        downloadDescriptor responsibleDirs

                    let readEncryptedPayload(encryptedPayload: array<byte>) =
                        encryptedPayload
                        |> Array.take
                            Constants.HiddenServices.DirectoryEncryption.SaltLength,
                        encryptedPayload
                        |> Array.skip
                            Constants.HiddenServices.DirectoryEncryption.SaltLength
                        |> Array.take(
                            encryptedPayload.Length
                            - Constants.HiddenServices.DirectoryEncryption.SaltLength
                            - Constants.HiddenServices.DirectoryEncryption.MacKeyLength
                        ),
                        encryptedPayload
                        |> Array.skip(
                            encryptedPayload.Length
                            - Constants.HiddenServices.DirectoryEncryption.MacKeyLength
                        )

                    let getDecryptionKeys(input: array<byte>) =
                        let keyBytes =
                            input
                            |> HiddenServicesCipher.CalculateShake256(
                                Constants.KeyS256Length
                                + Constants.IVS256Length
                                + Constants.HiddenServices.DirectoryEncryption.MacKeyLength
                            )

                        keyBytes |> Array.take Constants.KeyS256Length,
                        keyBytes
                        |> Array.skip Constants.KeyS256Length
                        |> Array.take Constants.IVS256Length,
                        keyBytes
                        |> Array.skip(
                            Constants.KeyS256Length + Constants.IVS256Length
                        )
                        |> Array.take
                            Constants.HiddenServices.DirectoryEncryption.MacKeyLength

                    let decryptDocument
                        (key: array<byte>)
                        (iv: array<byte>)
                        (encryptedData: array<byte>)
                        (parser: string -> 'T)
                        =
                        (TorStreamCipher(key, Some iv)
                            .Encrypt encryptedData
                         |> Encoding.ASCII.GetString)
                            .Trim('\000')
                        |> parser

                    let (firstLayerSalt, firstLayerEncryptedData, firstLayerMac) =
                        readEncryptedPayload
                            firstLayerDescriptorDocument.EncryptedPayload.Value

                    let secretInput =
                        Array.concat
                            [
                                blindedPublicKey
                                HiddenServicesCipher.GetSubCredential
                                    (periodNum, periodLength)
                                    publicKey
                                firstLayerDescriptorDocument.RevisionCounter.Value
                                |> uint64
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                            ]

                    let (firstLayerDecryptionKey,
                         firstLayerDecryptionIV,
                         firstLayerDecryptionMacKey) =
                        Array.concat
                            [
                                secretInput
                                firstLayerSalt
                                Constants.HiddenServices.DirectoryEncryption.SuperEncrypted
                                |> Encoding.ASCII.GetBytes
                            ]
                        |> getDecryptionKeys

                    let computedFirstLayerMac =
                        Array.concat
                            [
                                firstLayerDecryptionMacKey.Length
                                |> uint64
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                firstLayerDecryptionMacKey
                                firstLayerSalt.Length
                                |> uint64
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                firstLayerSalt
                                firstLayerEncryptedData
                            ]
                        |> HiddenServicesCipher.SHA3256

                    if
                        not
                            (
                                Enumerable.SequenceEqual(
                                    computedFirstLayerMac,
                                    firstLayerMac
                                )
                            )
                    then
                        failwith "First layer mac is not correct"

                    let (secondLayerSalt,
                         secondLayerEncryptedData,
                         secondLayerMac) =
                        let secondLayerDescriptorDocument =
                            decryptDocument
                                firstLayerDecryptionKey
                                firstLayerDecryptionIV
                                firstLayerEncryptedData
                                HiddenServiceSecondLayerDescriptorDocument.Parse

                        readEncryptedPayload
                            secondLayerDescriptorDocument.EncryptedPayload.Value

                    let (secondLayerDecryptionKey,
                         secondLayerDecryptionIV,
                         secondLayerDecryptionMacKey) =
                        Array.concat
                            [
                                secretInput
                                secondLayerSalt
                                Constants.HiddenServices.DirectoryEncryption.Encrypted
                                |> Encoding.ASCII.GetBytes
                            ]
                        |> getDecryptionKeys

                    let computedSecondLayerMac =
                        Array.concat
                            [
                                secondLayerDecryptionMacKey.Length
                                |> uint64
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                secondLayerDecryptionMacKey
                                secondLayerSalt.Length
                                |> uint64
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                secondLayerSalt
                                secondLayerEncryptedData
                            ]
                        |> HiddenServicesCipher.SHA3256

                    if
                        not
                            (
                                Enumerable.SequenceEqual(
                                    computedSecondLayerMac,
                                    secondLayerMac
                                )
                            )
                    then
                        failwith "Second layer mac is not correct"

                    let hiddenServiceDescriptorDocument =
                        decryptDocument
                            secondLayerDecryptionKey
                            secondLayerDecryptionIV
                            secondLayerEncryptedData
                            HiddenServiceDescriptorDocument.Parse

                    let introductionPointOpt =
                        hiddenServiceDescriptorDocument.IntroductionPoints
                        |> SeqUtils.TakeRandom 1
                        |> Seq.tryExactlyOne

                    match introductionPointOpt with
                    | None ->
                        return failwith "HS's introduction point list was empty"
                    | Some introductionPoint ->
                        let introductionPointAuthKey =
                            let authKeyBytes =
                                introductionPoint.AuthKey.Value.CertifiedKey

                            Ed25519PublicKeyParameters(authKeyBytes, 0)

                        let introductionPointEncKey =
                            X25519PublicKeyParameters(
                                introductionPoint.EncKey.Value,
                                0
                            )

                        let introductionPointNodeDetail =
                            use memStream =
                                new MemoryStream(
                                    introductionPoint.LinkSpecifiers.Value
                                )

                            use reader = new BinaryReader(memStream)

                            let rec readLinkSpecifier
                                (remainingLinkSpecifiers: int)
                                (state: List<LinkSpecifier>)
                                =
                                if remainingLinkSpecifiers = 0 then
                                    state
                                else
                                    LinkSpecifier.Deserialize reader
                                    |> List.singleton
                                    |> List.append state
                                    |> readLinkSpecifier(
                                        remainingLinkSpecifiers - 1
                                    )

                            let linkSpecifiers =
                                readLinkSpecifier
                                    (reader.ReadByte() |> int)
                                    List.empty

                            let endpointSpecifierOpt =
                                linkSpecifiers
                                |> List.tryFind(fun linkSpecifier ->
                                    linkSpecifier.Type = LinkSpecifierType.TLSOverTCPV4
                                )
                                |> Option.map(fun linkSpecifier ->
                                    linkSpecifier.ToEndPoint()
                                )

                            match endpointSpecifierOpt with
                            | None ->
                                failwith
                                    "Introduction point didn't have an IPV4 endpoint"
                            | Some endpointSpecifier ->
                                let identityKeyOpt =
                                    linkSpecifiers
                                    |> Seq.tryFind(fun linkSpecifier ->
                                        linkSpecifier.Type = LinkSpecifierType.LegacyIdentity
                                    )
                                    |> Option.map(fun linkSpecifier ->
                                        linkSpecifier.Data
                                    )

                                match identityKeyOpt with
                                | None ->
                                    failwith
                                        "Introduction point didn't have a legacy identity"
                                | Some identityKey ->
                                    CircuitNodeDetail.Create(
                                        endpointSpecifier,
                                        introductionPoint.OnionKey.Value,
                                        identityKey
                                    )

                        return
                            introductionPointAuthKey,
                            introductionPointEncKey,
                            introductionPointNodeDetail,
                            publicKey
                }

            let! introductionPointAuthKey,
                 introductionPointEncKey,
                 introductionPointNodeDetail,
                 pubKey = getIntroductionPointInfo()

            let randomGeneratedCookie =
                Array.zeroCreate Constants.RendezvousCookieLength

            RandomNumberGenerator
                .Create()
                .GetNonZeroBytes randomGeneratedCookie

            let! endpoint, guardnode = directory.AsyncGetRouter RouterType.Guard
            let! _, rendezvousNode = directory.AsyncGetRouter RouterType.Normal

            let! rendezvousGuard =
                TorGuard.AsyncNewClientWithIdentity
                    endpoint
                    (guardnode.GetIdentityKey() |> Some)

            let rendezvousCircuit = TorCircuit rendezvousGuard

            do! rendezvousCircuit.AsyncCreate guardnode |> Async.Ignore
            do! rendezvousCircuit.AsyncExtend rendezvousNode |> Async.Ignore

            do!
                rendezvousCircuit.AsyncRegisterAsRendezvousPoint
                    randomGeneratedCookie

            let randomPrivateKey, randomPublicKey =
                let kpGen = X25519KeyPairGenerator()
                let random = SecureRandom()
                kpGen.Init(X25519KeyGenerationParameters random)
                let keyPair = kpGen.GenerateKeyPair()

                keyPair.Private :?> X25519PrivateKeyParameters,
                keyPair.Public :?> X25519PublicKeyParameters

            match rendezvousNode with
            | Create(address, onionKey, identityKey) ->
                let introduceInnerData =
                    {
                        RelayIntroduceInnerData.OnionKey = onionKey
                        RendezvousCookie = randomGeneratedCookie
                        Extensions = List.empty
                        RendezvousLinkSpecifiers =
                            [
                                LinkSpecifier.CreateFromEndPoint address
                                {
                                    LinkSpecifier.Type =
                                        LinkSpecifierType.LegacyIdentity
                                    Data = identityKey
                                }
                            ]
                    }

                let! networkStatus = directory.AsyncGetLiveNetworkStatus()
                let periodInfo = networkStatus.GetTimePeriod()

                let data, macKey =
                    HiddenServicesCipher.EncryptIntroductionData
                        (introduceInnerData.ToBytes())
                        randomPrivateKey
                        randomPublicKey
                        introductionPointAuthKey
                        introductionPointEncKey
                        periodInfo
                        pubKey

                let introduce1Packet =
                    let introduce1PacketForMac =
                        {
                            RelayIntroduce.AuthKey =
                                RelayIntroAuthKey.ED25519SHA3256(
                                    introductionPointAuthKey.GetEncoded()
                                )
                            Extensions = List.empty
                            ClientPublicKey = randomPublicKey.GetEncoded()
                            Mac = Array.empty
                            EncryptedData = data
                        }

                    { introduce1PacketForMac with
                        Mac =
                            introduce1PacketForMac.ToBytes()
                            |> HiddenServicesCipher.CalculateMacWithSHA3256
                                macKey
                    }

                let introCircuit = TorCircuit rendezvousGuard

                do! introCircuit.AsyncCreate guardnode |> Async.Ignore

                do!
                    introCircuit.AsyncExtend introductionPointNodeDetail
                    |> Async.Ignore

                let rendezvousJoin =
                    rendezvousCircuit.AsyncWaitingForRendezvousJoin
                        randomPrivateKey
                        randomPublicKey
                        introductionPointAuthKey
                        introductionPointEncKey

                let introduceJob =
                    async {
                        let! ack = introCircuit.AsyncIntroduce introduce1Packet

                        if ack.Status <> RelayIntroduceStatus.Success then
                            return
                                raise
                                <| UnsuccessfulIntroductionException ack.Status
                    }

                do!
                    Async.Parallel [ introduceJob; rendezvousJoin ]
                    |> Async.Ignore

                // We can't use the "use" keyword since this stream needs
                // to outlive this function.
                let serviceStream = new TorStream(rendezvousCircuit)
                do! serviceStream.AsyncConnectToService port |> Async.Ignore

                return
                    {
                        RendezvousGuard = rendezvousGuard
                        RendezvousCircuit = rendezvousCircuit
                        Stream = serviceStream
                    }
            | _ ->
                return
                    failwith "Never happens. GetRouter never returns FastCreate"
        }

    interface IDisposable with
        member self.Dispose() =
            (self.RendezvousGuard :> IDisposable).Dispose()
