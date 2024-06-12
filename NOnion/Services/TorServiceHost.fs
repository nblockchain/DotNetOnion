namespace NOnion.Services

open System
open System.IO
open System.Net
open System.Net.Sockets
open System.Security.Cryptography
open System.Text
open System.Threading
open FSharpx.Collections

open Chaos.NaCl
open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Signers
open Org.BouncyCastle.Security

open NOnion
open NOnion.Cells.Relay
open NOnion.Crypto
open NOnion.Directory
open NOnion.Utility
open NOnion.Network
open NOnion.Http

type IntroductionPointInfo =
    {
        Address: IPEndPoint
        EncryptionKey: AsymmetricCipherKeyPair
        AuthKey: AsymmetricCipherKeyPair
        MasterPublicKey: Ed25519PublicKeyParameters
        NTorOnionKey: NTorOnionKey
        Fingerprint: Fingerprint
    }

type TorServiceHost
    (
        directory: TorDirectory,
        maxDescriptorUploadRetryCount: int,
        maxRendezvousConnectRetryCount: int,
        maybeMasterPrivateKey: Option<Ed25519PrivateKeyParameters>
    ) =

    let mutable introductionPointKeys: Map<string, IntroductionPointInfo> =
        Map.empty

    let mutable introductionPointDeadCounter = 0
    let incrementLock: obj = obj()

    let introductionPointDisconnectionToken: CancellationTokenSource =
        new CancellationTokenSource()

    let mutable guardNode: List<TorGuard> = List.empty
    let introductionPointSemaphore: SemaphoreLocker = SemaphoreLocker()
    let newClientSemaphore = new SemaphoreSlim(0)

    let masterPrivateKey, masterPublicKey =
        let masterPrivateKey =
            match maybeMasterPrivateKey with
            | Some masterPrivateKey when not(isNull masterPrivateKey) ->
                masterPrivateKey
            | _ ->
                let keyPair =
                    let kpGen = Ed25519KeyPairGenerator()
                    let random = SecureRandom()

                    kpGen.Init(Ed25519KeyGenerationParameters random)

                    kpGen.GenerateKeyPair()

                keyPair.Private :?> Ed25519PrivateKeyParameters

        masterPrivateKey, masterPrivateKey.GeneratePublicKey()

    let descriptorSigningPublicKey, descriptorSigningPrivateKey =
        let keyPair =
            let kpGen = Ed25519KeyPairGenerator()
            let random = SecureRandom()

            kpGen.Init(Ed25519KeyGenerationParameters random)
            kpGen.GenerateKeyPair()

        keyPair.Public :?> Ed25519PublicKeyParameters,
        keyPair.Private :?> Ed25519PrivateKeyParameters

    let mutable pendingConnectionQueue: Queue<uint16 * TorCircuit> = Queue.empty
    let queueLock: SemaphoreLocker = SemaphoreLocker()

    member private self.IncomingServiceStreamCallback
        (streamId: uint16)
        (senderCircuit: TorCircuit)
        =
        async {
            let registerConnectionRequest() =
                pendingConnectionQueue <-
                    pendingConnectionQueue.Conj(streamId, senderCircuit)

                newClientSemaphore.Release() |> ignore<int>

            queueLock.RunSyncWithSemaphore registerConnectionRequest
        }

    member private self.IntroductionPointDeathCallback() =
        lock
            incrementLock
            (fun () ->
                introductionPointDeadCounter <- introductionPointDeadCounter + 1

                //If more than half of the introduction points are dead, TorServiceHost is dead!
                if introductionPointDeadCounter > Constants.HiddenServices.IntroductionPointCount
                                                  / 2 then
                    introductionPointDisconnectionToken.Cancel()
            )

    member private self.RelayIntroduceCallback(introduce: RelayIntroduce) =
        let rec tryConnectingToRendezvous
            rendezvousEndpoint
            rendezvousFingerPrint
            onionKey
            cookie
            clientPubKey
            introAuthPubKey
            introEncPrivKey
            introEncPubKey
            =
            async {
                let! endPoint, randomNodeDetails =
                    directory.GetRouter RouterType.Guard

                let! guard =
                    TorGuard.NewClientWithIdentity
                        endPoint
                        (randomNodeDetails.GetIdentityKey() |> Some)

                let rendezvousCircuit =
                    TorCircuit(guard, self.IncomingServiceStreamCallback)

                do! rendezvousCircuit.Create randomNodeDetails |> Async.Ignore

                do!
                    rendezvousCircuit.Extend(
                        CircuitNodeDetail.Create(
                            rendezvousEndpoint,
                            onionKey,
                            rendezvousFingerPrint
                        )
                    )
                    |> Async.Ignore

                do!
                    rendezvousCircuit.Rendezvous
                        cookie
                        (X25519PublicKeyParameters(clientPubKey, 0))
                        introAuthPubKey
                        introEncPrivKey
                        introEncPubKey
            }

        async {
            let introductionPointDetails =
                match introduce.AuthKey with
                | RelayIntroAuthKey.ED25519SHA3256 bytes ->
                    match
                        introductionPointKeys.TryGetValue
                            (Convert.ToBase64String bytes)
                        with
                    | false, _ -> failwith "Unknown introduction point"
                    | true, details -> details
                | _ -> failwith "Unreachable, legacy keys are not implemented"

            let introAuthPubKey =
                introductionPointDetails.AuthKey.Public
                :?> Ed25519PublicKeyParameters

            let introEncPubKey =
                introductionPointDetails.EncryptionKey.Public
                :?> X25519PublicKeyParameters

            let introEncPrivKey =
                introductionPointDetails.EncryptionKey.Private
                :?> X25519PrivateKeyParameters

            let! networkStatus = directory.GetLiveNetworkStatus()
            let periodInfo = networkStatus.GetTimePeriod()

            let decryptedData, macKey =
                HiddenServicesCipher.DecryptIntroductionData
                    introduce.EncryptedData
                    (X25519PublicKeyParameters(introduce.ClientPublicKey, 0))
                    (introductionPointDetails.AuthKey.Public
                    :?> Ed25519PublicKeyParameters)
                    (introductionPointDetails.EncryptionKey.Private
                    :?> X25519PrivateKeyParameters)
                    (introductionPointDetails.EncryptionKey.Public
                    :?> X25519PublicKeyParameters)
                    periodInfo
                    (introductionPointDetails.MasterPublicKey.GetEncoded())

            use decryptedStream = new MemoryStream(decryptedData)
            use decryptedReader = new BinaryReader(decryptedStream)
            let innerData = RelayIntroduceInnerData.Deserialize decryptedReader

            let digest =
                let introduceForMac =
                    { introduce with
                        Mac = Array.empty
                    }

                introduceForMac.ToBytes()
                |> HiddenServicesCipher.CalculateMacWithSHA3256 macKey

            if digest <> introduce.Mac then
                failwith "Invalid mac"

            let rendezvousEndpoint =
                let linkSpecifierOpt =
                    innerData.RendezvousLinkSpecifiers
                    |> Seq.filter(fun linkS ->
                        linkS.Type = LinkSpecifierType.TLSOverTCPV4
                    )
                    |> Seq.tryExactlyOne

                match linkSpecifierOpt with
                | Some linkSpecifier -> linkSpecifier.ToEndPoint()
                | None -> failwith "No rendezvous endpoint found!"

            let rendezvousFingerPrint =
                let linkSpecifierOpt =
                    innerData.RendezvousLinkSpecifiers
                    |> Seq.filter(fun linkS ->
                        linkS.Type = LinkSpecifierType.LegacyIdentity
                    )
                    |> Seq.tryExactlyOne

                match linkSpecifierOpt with
                | Some linkSpecifier -> Fingerprint linkSpecifier.Data
                | None -> failwith "No rendezvous fingerprint found!"

            let connectToRendezvousJob =
                tryConnectingToRendezvous
                    rendezvousEndpoint
                    rendezvousFingerPrint
                    innerData.OnionKey
                    innerData.RendezvousCookie
                    introduce.ClientPublicKey
                    introAuthPubKey
                    introEncPrivKey
                    introEncPubKey

            do!
                FSharpUtil.Retry<SocketException, NOnionException>
                    connectToRendezvousJob
                    maxRendezvousConnectRetryCount

            return ()
        }

    member self.StartAsync() =
        self.Start() |> Async.StartAsTask

    member self.RegisterIntroductionPoints() =
        async {
            let rec createIntroductionPoint() =
                async {
                    try
                        let! guardEndPoint, guardNodeDetail =
                            directory.GetRouter RouterType.Guard

                        let! _, introNodeDetail =
                            directory.GetRouter RouterType.Normal

                        match introNodeDetail with
                        | FastCreate ->
                            return
                                failwith
                                    "Unreachable, directory always returns non-fast connection info"
                        | Create(address, onionKey, fingerprint) ->
                            let! guard =
                                TorGuard.NewClientWithIdentity
                                    guardEndPoint
                                    (guardNodeDetail.GetIdentityKey() |> Some)

                            let circuit = TorCircuit guard

                            let encKeyPair, authKeyPair =
                                let kpGen = Ed25519KeyPairGenerator()
                                let kpGenX = X25519KeyPairGenerator()

                                let random = SecureRandom()

                                kpGen.Init(
                                    Ed25519KeyGenerationParameters random
                                )

                                kpGenX.Init(
                                    X25519KeyGenerationParameters random
                                )

                                kpGenX.GenerateKeyPair(),
                                kpGen.GenerateKeyPair()

                            let introductionPointInfo =
                                {
                                    IntroductionPointInfo.Address = address
                                    AuthKey = authKeyPair
                                    EncryptionKey = encKeyPair
                                    NTorOnionKey = onionKey
                                    Fingerprint = fingerprint
                                    MasterPublicKey = masterPublicKey
                                }

                            do! circuit.Create guardNodeDetail |> Async.Ignore
                            do! circuit.Extend introNodeDetail |> Async.Ignore

                            do!
                                circuit.RegisterAsIntroductionPoint
                                    (Some authKeyPair)
                                    self.RelayIntroduceCallback
                                    self.IntroductionPointDeathCallback

                            let safeRegister() =
                                let introductionPointAlreadyExists =
                                    introductionPointKeys
                                    |> Map.toSeq
                                    |> Seq.exists(fun (_authKey, info) ->
                                        info.Address = introductionPointInfo.Address
                                    )

                                if introductionPointAlreadyExists then
                                    failwith
                                        "duplicate introduction point, try again!"
                                else
                                    guardNode <- guard :: guardNode

                                    introductionPointKeys <-
                                        Map.add
                                            ((authKeyPair.Public
                                             :?> Ed25519PublicKeyParameters)
                                                 .GetEncoded()
                                             |> Convert.ToBase64String)
                                            introductionPointInfo
                                            introductionPointKeys

                            introductionPointSemaphore.RunSyncWithSemaphore
                                safeRegister
                    with
                    | ex ->
                        TorLogger.Log(
                            sprintf
                                "TorServiceHost: failed to register introduction point, ex=%s"
                                (ex.ToString())
                        )

                        return! createIntroductionPoint()

                }

            do!
                Seq.replicate
                    Constants.HiddenServices.IntroductionPointCount
                    (createIntroductionPoint())
                |> Async.Parallel
                |> Async.Ignore
        }

    member self.UploadDescriptor
        (directoryToUploadTo: string)
        (document: HiddenServiceFirstLayerDescriptorDocument)
        (retry: int)
        =
        async {
            if retry > maxDescriptorUploadRetryCount then
                return ()
            else
                try
                    let! hsDirectoryNode =
                        directory.GetCircuitNodeDetailByIdentity
                            directoryToUploadTo

                    let! guardEndPoint, randomGuardNode =
                        directory.GetRouter RouterType.Guard

                    let! _, randomMiddleNode =
                        directory.GetRouter RouterType.Normal

                    use! guardNode =
                        TorGuard.NewClientWithIdentity
                            guardEndPoint
                            (randomGuardNode.GetIdentityKey() |> Some)

                    let circuit = TorCircuit guardNode
                    do! circuit.Create randomGuardNode |> Async.Ignore
                    do! circuit.Extend randomMiddleNode |> Async.Ignore
                    do! circuit.Extend hsDirectoryNode |> Async.Ignore

                    use dirStream = new TorStream(circuit)
                    do! dirStream.ConnectToDirectory() |> Async.Ignore

                    let! _response =
                        TorHttpClient(
                            dirStream,
                            Constants.DefaultHttpHost
                        )
                            .PostString
                            (sprintf
                                "/tor/hs/%i/publish"
                                Constants.HiddenServices.Version)
                            (document.ToString())

                    TorLogger.Log(
                        sprintf
                            "TorServiceHost: descriptor uploaded to node with identity %s"
                            directoryToUploadTo
                    )

                    return ()
                with
                | :? UnsuccessfulHttpResponseException ->
                    // During testing, after migration to microdescriptor, we saw instances of
                    // 404 error msg when trying to publish our descriptors which mean for
                    // some reason we're trying to upload descriptor to a directory that
                    // is not a hidden service directory, there is no point in retrying here.
                    return ()
                | ex ->
                    TorLogger.Log(
                        sprintf
                            "TorServiceHost: hs descriptor upload failed, ex=%s"
                            (ex.ToString())
                    )

                    return!
                        self.UploadDescriptor
                            directoryToUploadTo
                            document
                            (retry + 1)
        }

    member self.BuildAndUploadDescriptor
        periodNum
        periodLength
        srv
        (srvStartTime: DateTime)
        =
        async {
            let blindedPublicKey =
                HiddenServicesCipher.BuildBlindedPublicKey
                    (periodNum, periodLength)
                    (masterPublicKey.GetEncoded())

            let! responsibleDirs =
                directory.GetResponsibleHiddenServiceDirectories
                    blindedPublicKey
                    srv
                    periodNum
                    periodLength
                    Constants.HiddenServices.Hashring.SpreadStore

            let revisionCounter =
                //FIXME(PRIVACY): this should be encrypted with an OPE cipher
                //to mask server's time skew
                (DateTime.UtcNow - srvStartTime).TotalSeconds |> int64 |> Some

            let getEncryptionKeys(input: array<byte>) =
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
                |> Array.skip(Constants.KeyS256Length + Constants.IVS256Length)
                |> Array.take
                    Constants.HiddenServices.DirectoryEncryption.MacKeyLength

            let secretInput =
                Array.concat
                    [
                        blindedPublicKey.ToByteArray()
                        HiddenServicesCipher.GetSubCredential
                            (periodNum, periodLength)
                            (masterPublicKey.GetEncoded())
                        revisionCounter.Value
                        |> uint64
                        |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                    ]

            let outerWrapper =
                let encryptedSecondLayer =
                    let encryptedFirstLayer =
                        let innerCoreInBytes =
                            let createIntoductionPointEntry
                                (info: IntroductionPointInfo)
                                =
                                let linkSpecifiersInBytes =
                                    let linkSpecifiers =
                                        [
                                            LinkSpecifier.CreateFromEndPoint
                                                info.Address
                                            {
                                                LinkSpecifier.Type =
                                                    LinkSpecifierType.LegacyIdentity
                                                Data =
                                                    info.Fingerprint.ToByteArray
                                                        ()
                                            }
                                        ]

                                    Array.concat
                                        [
                                            linkSpecifiers.Length
                                            |> byte
                                            |> Array.singleton
                                            linkSpecifiers
                                            |> List.map(fun link ->
                                                link.ToBytes()
                                            )
                                            |> Array.concat
                                        ]

                                let authKeyCert =
                                    Certificate.CreateNew
                                        CertType.IntroPointAuthKeySignedByDescriptorSigningKey
                                        ((info.AuthKey.Public
                                        :?> Ed25519PublicKeyParameters)
                                            .GetEncoded())
                                        (descriptorSigningPublicKey
                                         |> ED25519PublicKey)
                                        (descriptorSigningPrivateKey
                                         |> Ed25519PrivateKey.Normal)
                                        Constants.HiddenServices.Descriptor.CertificateLifetime

                                let encKeyBytes =
                                    (info.EncryptionKey.Public
                                    :?> X25519PublicKeyParameters)
                                        .GetEncoded()

                                let encKeyCert =
                                    let convertedX25519Key =
                                        match
                                            Ed25519.Ed25519PublicKeyFromCurve25519
                                                (
                                                    encKeyBytes,
                                                    false
                                                )
                                            with
                                        | true, output -> output
                                        | false, _ ->
                                            failwith
                                                "Should not happen, Ed25519PublicKeyFromCurve25519 will never return false"

                                    Certificate.CreateNew
                                        CertType.IntroPointEncKeySignedByDescriptorSigningKey
                                        convertedX25519Key
                                        (descriptorSigningPublicKey
                                         |> ED25519PublicKey)
                                        (descriptorSigningPrivateKey
                                         |> Ed25519PrivateKey.Normal)
                                        Constants.HiddenServices.Descriptor.CertificateLifetime

                                {
                                    IntroductionPointEntry.OnionKey =
                                        Some info.NTorOnionKey
                                    AuthKey = Some authKeyCert
                                    EncKey = Some encKeyBytes
                                    EncKeyCert = Some encKeyCert
                                    LinkSpecifiers =
                                        linkSpecifiersInBytes |> Some
                                }

                            { HiddenServiceDescriptorDocument.Default with
                                IsSingleOnionService = false
                                IntroductionPoints =
                                    introductionPointKeys
                                    |> Map.values
                                    |> Seq.map createIntoductionPointEntry
                                    |> Seq.toList
                            }
                                .ToString()
                            |> Encoding.ASCII.GetBytes

                        let firstLayerSalt =
                            let salt =
                                Array.zeroCreate
                                    Constants.HiddenServices.DirectoryEncryption.SaltLength

                            RandomNumberGenerator.Create().GetBytes salt
                            salt

                        let firstLayerKey, firstLayerIV, firstLayerMacKey =
                            Array.concat
                                [
                                    secretInput
                                    firstLayerSalt
                                    Constants.HiddenServices.DirectoryEncryption.Encrypted
                                    |> Encoding.ASCII.GetBytes
                                ]
                            |> getEncryptionKeys

                        let firstLayerEncryptedData =
                            TorStreamCipher(firstLayerKey, Some firstLayerIV)
                                .Encrypt innerCoreInBytes

                        let computedFirstLayerMac =
                            HiddenServicesCipher.CalculateDirectoryEncryptionMac
                                firstLayerMacKey
                                firstLayerSalt
                                firstLayerEncryptedData

                        Array.concat
                            [
                                firstLayerSalt
                                firstLayerEncryptedData
                                computedFirstLayerMac
                            ]

                    let secondLayerPlainText =
                        {
                            HiddenServiceSecondLayerDescriptorDocument.EncryptedPayload =
                                Some encryptedFirstLayer
                        }
                            .ToString()
                        |> Encoding.ASCII.GetBytes

                    let paddedSecondLayerPlainText =
                        let paddedLength =
                            // Before encryption the plaintext is padded with NUL bytes to the nearest multiple of 10k bytes.
                            let pad = 10000
                            (secondLayerPlainText.Length + pad - 1) / pad * pad

                        Array.zeroCreate paddedLength

                    Array.Copy(
                        secondLayerPlainText,
                        paddedSecondLayerPlainText,
                        secondLayerPlainText.Length
                    )

                    let secondLayerSalt =
                        let salt =
                            Array.zeroCreate
                                Constants.HiddenServices.DirectoryEncryption.SaltLength

                        RandomNumberGenerator.Create().GetBytes salt
                        salt

                    let secondLayerKey, secondLayerIV, secondLayerMacKey =
                        Array.concat
                            [
                                secretInput
                                secondLayerSalt
                                Constants.HiddenServices.DirectoryEncryption.SuperEncrypted
                                |> Encoding.ASCII.GetBytes
                            ]
                        |> getEncryptionKeys

                    let secondLayerEncryptedData =
                        TorStreamCipher(secondLayerKey, Some secondLayerIV)
                            .Encrypt paddedSecondLayerPlainText

                    let computedSecondLayerMac =
                        HiddenServicesCipher.CalculateDirectoryEncryptionMac
                            secondLayerMacKey
                            secondLayerSalt
                            secondLayerEncryptedData

                    Array.concat
                        [
                            secondLayerSalt
                            secondLayerEncryptedData
                            computedSecondLayerMac
                        ]

                let descriptorSigningKeyCert =
                    let blindedPrivateKey =
                        HiddenServicesCipher.BuildExpandedBlindedPrivateKey
                            (periodNum, periodLength)
                            (masterPublicKey.GetEncoded())
                            (masterPrivateKey.GetEncoded())

                    Certificate.CreateNew
                        CertType.ShortTermDescriptorSigningKeyByBlindedPublicKey
                        (descriptorSigningPublicKey.GetEncoded())
                        blindedPublicKey
                        (Ed25519PrivateKey.Expanded blindedPrivateKey)
                        Constants.HiddenServices.Descriptor.CertificateLifetime

                HiddenServiceFirstLayerDescriptorDocument.CreateNew
                    Constants.HiddenServices.Version
                    Constants.HiddenServices.Descriptor.Lifetime
                    descriptorSigningKeyCert
                    revisionCounter
                    encryptedSecondLayer
                    descriptorSigningPrivateKey

            let jobs =
                responsibleDirs
                |> Seq.map(fun dir -> self.UploadDescriptor dir outerWrapper 1)

            do!
                Async.Parallel(
                    jobs,
                    maxDegreeOfParallelism =
                        Constants.HiddenServices.Hashring.SpreadStore
                )
                |> Async.Ignore
        }

    member self.UpdateSecondDescriptor(networkStatus: NetworkStatusDocument) =
        let srv = networkStatus.SharedRandomCurrentValue.Value

        let srvStartTime =
            HiddenServicesUtility.GetStartTimeOfCurrentSRVProtocolRun
                (networkStatus.GetValidAfter())
                (networkStatus.GetVotingInterval())

        let periodNum, periodLength =
            let periodNum, periodLength = networkStatus.GetTimePeriod()

            if
                HiddenServicesUtility.InPeriodBetweenTPAndSRV
                    (networkStatus.GetValidAfter())
                    (networkStatus.GetVotingInterval())
                    (networkStatus.GetHiddenServicesDirectoryInterval()) then
                periodNum, periodLength
            else
                periodNum + 1UL, periodLength

        self.BuildAndUploadDescriptor periodNum periodLength srv srvStartTime

    member self.UpdateFirstDescriptor(networkStatus: NetworkStatusDocument) =
        let srv = networkStatus.SharedRandomPreviousValue.Value

        let srvStartTime =
            HiddenServicesUtility.GetStartTimeOfPreviousSRVProtocolRun
                (networkStatus.GetValidAfter())
                (networkStatus.GetVotingInterval())

        let periodNum, periodLength =
            let periodNum, periodLength = networkStatus.GetTimePeriod()

            if
                HiddenServicesUtility.InPeriodBetweenTPAndSRV
                    (networkStatus.GetValidAfter())
                    (networkStatus.GetVotingInterval())
                    (networkStatus.GetHiddenServicesDirectoryInterval()) then
                periodNum - 1UL, periodLength
            else
                periodNum, periodLength

        self.BuildAndUploadDescriptor periodNum periodLength srv srvStartTime

    //TODO: this should refresh every 60-120min
    member self.KeepDescriptorsUpToDate() =
        async {
            let! networkStatus = directory.GetLiveNetworkStatus()

            let firstDescriptorBuildJob =
                self.UpdateFirstDescriptor networkStatus

            let secondDescriptorBuildJob =
                self.UpdateSecondDescriptor networkStatus

            do!
                Async.Parallel
                    [|
                        firstDescriptorBuildJob
                        secondDescriptorBuildJob
                    |]
                |> Async.Ignore
        }

    member self.Start() =
        async {
            do! self.RegisterIntroductionPoints()

            do! self.KeepDescriptorsUpToDate()
        }

    member __.AcceptClient() =
        async {
            let! cancelToken = Async.CancellationToken
            cancelToken.ThrowIfCancellationRequested()

            let linkedCts =
                CancellationTokenSource.CreateLinkedTokenSource(
                    cancelToken,
                    introductionPointDisconnectionToken.Token
                )

            let tryGetConnectionRequest() =
                let nextItemOpt = pendingConnectionQueue.TryUncons

                match nextItemOpt with
                | Some(nextItem, rest) ->
                    pendingConnectionQueue <- rest
                    Some nextItem
                | None -> None

            let rec getConnectionRequest() =
                async {
                    try
                        do!
                            newClientSemaphore.WaitAsync linkedCts.Token
                            |> Async.AwaitTask
                    with
                    | :? OperationCanceledException as ex ->
                        if introductionPointDisconnectionToken.IsCancellationRequested then
                            return raise <| IntroductoinPointsKilledException()
                        else
                            return raise <| FSharpUtil.ReRaise ex

                    let nextItemOpt =
                        queueLock.RunSyncWithSemaphore tryGetConnectionRequest

                    match nextItemOpt with
                    | Some nextItem -> return nextItem
                    | None -> return failwith "should not happen"
                }

            let! (streamId, senderCircuit) = getConnectionRequest()
            // We can't use the "use" keyword since this stream needs
            // to outlive this function. Hopefully the caller will dispose
            // this after they're done using it.
            let! stream = TorStream.Accept streamId senderCircuit
            return stream
        }

    member self.AcceptClientAsync() =
        self.AcceptClient() |> Async.StartAsTask

    member self.AcceptClientAsync(cancellationToken: CancellationToken) =
        Async.StartAsTask(
            self.AcceptClient(),
            cancellationToken = cancellationToken
        )

    member self.ExportUrl() =
        let publicKey = masterPublicKey.GetEncoded()

        let checksum =
            Array.concat
                [
                    Constants.HiddenServices.OnionUrl.ChecksumPrefix
                    |> System.Text.Encoding.ASCII.GetBytes
                    publicKey
                    Constants.HiddenServices.Version |> byte |> Array.singleton
                ]
            |> HiddenServicesCipher.SHA3256
            |> Seq.take Constants.HiddenServices.OnionUrl.ChecksumLength
            |> Seq.toArray

        (Array.concat
            [
                publicKey
                checksum
                Constants.HiddenServices.Version |> byte |> Array.singleton
            ]
         |> Base32Util.EncodeBase32)
            .ToLower()
        + ".onion"

    member self.ExportPrivateKey() =
        masterPrivateKey

    interface IDisposable with
        member __.Dispose() =
            for guard in guardNode do
                (guard :> IDisposable).Dispose()
