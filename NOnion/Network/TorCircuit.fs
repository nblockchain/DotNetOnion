namespace NOnion.Network

open System
open System.Security.Cryptography
open System.Threading.Tasks
open System.Net
open System.Net.Sockets

open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Security
open FSharpx.Collections

open NOnion
open NOnion.Cells
open NOnion.Cells.Relay
open NOnion.Crypto
open NOnion.Crypto.Kdf
open NOnion.TorHandshakes
open NOnion.Utility
open MailboxResultUtil

type CircuitNodeDetail =
    | FastCreate
    | Create of
        EndPoint: IPEndPoint *
        NTorOnionKey: array<byte> *
        IdentityKey: array<byte>

    member self.GetIdentityKey() =
        match self with
        | Create(_endpoint, _onionKey, identityKey) -> identityKey
        | FastCreate -> failwith "GetIdentityKey was called on FastCreate"

type private CircuitIdTaskResult = OperationResult<Task<uint16>>

type private RequestSendIntroduceResult =
    OperationResult<Task<RelayIntroduceAck>>

type private TaskResult = OperationResult<Task>

type private UnitResult = OperationResult<unit>

[<RequireQualifiedAccess>]
type private CircuitOperation =
    | GetCircuitLastNode of
        replyChannel: AsyncReplyChannel<OperationResult<TorCircuitNode>>
    | SendRelayCell of
        streamId: uint16 *
        relayData: RelayData *
        customDestinationOpt: Option<TorCircuitNode> *
        replyChannel: AsyncReplyChannel<UnitResult>
    | HandleIncomingCell of
        circuit: TorCircuit *
        cell: ICell *
        replyChannel: AsyncReplyChannel<UnitResult>
    | Create of
        circuitObj: ITorCircuit *
        guardDetailInfo: CircuitNodeDetail *
        replyChannel: AsyncReplyChannel<CircuitIdTaskResult>
    | Extend of
        guardDetailInfo: CircuitNodeDetail *
        replyChannel: AsyncReplyChannel<CircuitIdTaskResult>
    | RegisterAsIntroductionPoint of
        authKeyPairOpt: Option<AsymmetricCipherKeyPair> *
        callback: (RelayIntroduce -> Async<unit>) *
        disconnectionCallback: (unit -> unit) *
        replyChannel: AsyncReplyChannel<TaskResult>
    | RegisterAsRendezvousPoint of
        cookie: array<byte> *
        replyChannel: AsyncReplyChannel<TaskResult>
    | SendIntroduceRequest of
        introduceMsg: RelayIntroduce *
        replyChannel: AsyncReplyChannel<RequestSendIntroduceResult>
    | WaitForRendezvous of
        clientRandomPrivateKey: X25519PrivateKeyParameters *
        clientRandomPublicKey: X25519PublicKeyParameters *
        introAuthPublicKey: Ed25519PublicKeyParameters *
        introEncPublicKey: X25519PublicKeyParameters *
        replyChannel: AsyncReplyChannel<TaskResult>
    | SendRendezvousRequest of
        cookie: array<byte> *
        clientRandomKey: X25519PublicKeyParameters *
        introAuthPublicKey: Ed25519PublicKeyParameters *
        introEncPrivateKey: X25519PrivateKeyParameters *
        introEncPublicKey: X25519PublicKeyParameters *
        replyChannel: AsyncReplyChannel<UnitResult>
    | HandleDeath

and TorCircuit
    private
    (
        guard: TorGuard,
        serviceStreamCallback: Option<uint16 -> TorCircuit -> Async<unit>>
    ) =
    let mutable circuitState: CircuitState = CircuitState.Initialized

    let mutable streamsCount: int = 1
    let mutable streamsMap: Map<uint16, ITorStream> = Map.empty
    // Prevents two stream setup happening at once (to prevent race condition on writing to StreamIds list)
    let streamSetupLock: obj = obj()

    let rec CircuitMailBoxProcessor(inbox: MailboxProcessor<CircuitOperation>) =
        let announceDeath() =
            TorLogger.Log "TorCircuit: circuit is dead, telling children..."

            let killStreams() =
                streamsMap
                |> Map.iter(fun _sid stream -> stream.HandleDestroyedCircuit())

            lock streamSetupLock killStreams

            match circuitState with
            | Creating(circuitId, _, _)
            | Extending(circuitId, _, _, _)
            | RegisteringAsIntroductionPoint(circuitId, _, _, _, _, _, _)
            | RegisteringAsRendezvousPoint(circuitId, _, _)
            | WaitingForIntroduceAcknowledge(circuitId, _, _)
            | WaitingForRendezvousRequest(circuitId, _, _, _, _, _, _)
            | Ready(circuitId, _)

            | ReadyAsRendezvousPoint(circuitId, _)
            | Destroyed(circuitId, _)
            | Truncated(circuitId, _)
            | Disconnected circuitId -> circuitState <- Disconnected circuitId
            | ReadyAsIntroductionPoint
                (
                    circuitId, _, _, _, _, disconnectionCallback
                ) ->
                circuitState <- Disconnected circuitId
                disconnectionCallback()
            | CircuitState.Initialized ->
                failwith
                    "Should not happen: a non-initialized circuit can't die"

        let getCircuitLastNode() =
            match circuitState with
            | Ready(_, nodesStates) ->
                let lastNodeOpt = nodesStates |> List.rev |> List.tryHead

                match lastNodeOpt with
                | None -> failwith "BUG: circuit has no nodes"
                | Some lastNode -> lastNode
            | _ ->
                failwith
                    "Unexpected state when trying to find the last circuit node"

        let internalSendRelayCell
            (streamId: uint16)
            (relayData: RelayData)
            (customDestinationOpt: Option<TorCircuitNode>)
            (early: bool)
            =
            async {
                match circuitState with
                | Ready(circuitId, nodesStates)
                | Extending(circuitId, _, nodesStates, _)
                | RegisteringAsIntroductionPoint
                    (
                        circuitId, nodesStates, _, _, _, _, _
                    )
                | WaitingForIntroduceAcknowledge(circuitId, nodesStates, _)
                | RegisteringAsRendezvousPoint(circuitId, nodesStates, _) ->
                    let onionList, destination =
                        match customDestinationOpt with
                        | None ->
                            let reversedNodesList = nodesStates |> Seq.rev

                            let destinationNodeOpt =
                                reversedNodesList |> Seq.tryHead

                            match destinationNodeOpt with
                            | None ->
                                failwith
                                    "Circuit has no nodes, can't relay data"
                            | Some destinationNode ->
                                reversedNodesList, destinationNode
                        | Some destination ->
                            nodesStates
                            |> Seq.takeWhile(fun node -> node <> destination)
                            |> Seq.append(Seq.singleton destination)
                            |> Seq.rev,
                            destination

                    let plainRelayCell =
                        CellPlainRelay.Create
                            streamId
                            relayData
                            (Array.zeroCreate Constants.RelayDigestLength)

                    let relayPlainBytes = plainRelayCell.ToBytes true

                    destination.CryptoState.ForwardDigest.Update
                        relayPlainBytes
                        0
                        relayPlainBytes.Length

                    let digest =
                        destination.CryptoState.ForwardDigest.GetDigestBytes()
                        |> Array.take Constants.RelayDigestLength

                    let plainRelayCell =
                        { plainRelayCell with
                            Digest = digest
                        }

                    let rec encryptMessage
                        (nodes: seq<TorCircuitNode>)
                        (message: array<byte>)
                        =
                        match Seq.tryHeadTail nodes with
                        | Some(node, nextNodes) ->
                            encryptMessage
                                nextNodes
                                (node.CryptoState.ForwardCipher.Encrypt message)
                        | None -> message

                    do!
                        {
                            CellEncryptedRelay.EncryptedData =
                                plainRelayCell.ToBytes false
                                |> encryptMessage onionList
                            Early = early
                        }
                        |> guard.Send circuitId

                    match relayData with
                    | RelayData _
                    | RelaySendMe _ ->
                        // too many to log
                        ()
                    | _ ->
                        TorLogger.Log(
                            sprintf
                                "TorCircuit[%i,%s]: Sent relay cell %A over circuit"
                                circuitId
                                circuitState.Name
                                relayData
                        )
                | _ ->
                    failwithf
                        "Can't relay cell over circuit, %s state"
                        (circuitState.ToString())
            }

        let sendRelayCell streamId relayData customDestinationOpt =
            async {
                match circuitState with
                | Ready _ ->
                    return!
                        internalSendRelayCell
                            streamId
                            relayData
                            customDestinationOpt
                            false
                | _ ->
                    return
                        failwithf
                            "Can't relay cell over circuit, %s state"
                            (circuitState.ToString())
            }

        let decryptCell(encryptedRelayCell: CellEncryptedRelay) =
            match circuitState with
            | Ready(circuitId, nodes)
            | ReadyAsIntroductionPoint(circuitId, nodes, _, _, _, _)
            | ReadyAsRendezvousPoint(circuitId, nodes)
            | RegisteringAsIntroductionPoint(circuitId, nodes, _, _, _, _, _)
            | RegisteringAsRendezvousPoint(circuitId, nodes, _)
            | WaitingForIntroduceAcknowledge(circuitId, nodes, _)
            | WaitingForRendezvousRequest(circuitId, nodes, _, _, _, _, _)
            | Extending(circuitId, _, nodes, _) ->
                let rec decryptMessage
                    (message: array<byte>)
                    (nodes: List<TorCircuitNode>)
                    =
                    match List.tryHead nodes with
                    | Some node ->
                        let decryptedRelayCellBytes =
                            node.CryptoState.BackwardCipher.Encrypt message

                        let recognized =
                            System.BitConverter.ToUInt16(
                                decryptedRelayCellBytes,
                                Constants.RelayRecognizedOffset
                            )

                        if recognized <> Constants.RecognizedDefaultValue then
                            decryptMessage decryptedRelayCellBytes nodes.Tail
                        else
                            let digest =
                                decryptedRelayCellBytes
                                |> Array.skip Constants.RelayDigestOffset
                                |> Array.take Constants.RelayDigestLength

                            Array.fill
                                decryptedRelayCellBytes
                                Constants.RelayDigestOffset
                                Constants.RelayDigestLength
                                0uy

                            let computedDigest =
                                node.CryptoState.BackwardDigest.PeekDigest
                                    decryptedRelayCellBytes
                                    0
                                    decryptedRelayCellBytes.Length
                                |> Array.take Constants.RelayDigestLength

                            if digest <> computedDigest then
                                decryptMessage
                                    decryptedRelayCellBytes
                                    nodes.Tail
                            else
                                node.CryptoState.BackwardDigest.Update
                                    decryptedRelayCellBytes
                                    0
                                    decryptedRelayCellBytes.Length

                                let decryptedRelayCell =
                                    CellPlainRelay.FromBytes
                                        decryptedRelayCellBytes


                                match decryptedRelayCell.Data with
                                | RelayData _
                                | RelaySendMe _ ->
                                    //Too many to log
                                    ()
                                | _ ->
                                    TorLogger.Log(
                                        sprintf
                                            "TorCircuit[%i,%s]: decrypted relay cell %A over circuit"
                                            circuitId
                                            circuitState.Name
                                            decryptedRelayCell.Data
                                    )

                                (decryptedRelayCell.StreamId,
                                 decryptedRelayCell.Data,
                                 node)
                    | None ->
                        announceDeath()

                        raise <| CircuitDecryptionFailedException()

                decryptMessage encryptedRelayCell.EncryptedData nodes
            | _ -> failwith "Unexpected state when receiving relay cell"

        let handleIncomingCell (circuitObj: TorCircuit) (cell: ICell) =
            async {
                //TODO: Handle circuit-level cells like destroy/truncate etc..
                match cell with
                | :? ICreatedCell as createdMsg ->
                    match circuitState with
                    | Creating(circuitId, handshakeState, tcs) ->
                        let kdfResult =
                            handshakeState.GenerateKdfResult createdMsg

                        circuitState <-
                            Ready(
                                circuitId,
                                List.singleton
                                    {
                                        TorCircuitNode.CryptoState =
                                            TorCryptoState.FromKdfResult
                                                kdfResult
                                                false
                                        Window =
                                            TorWindow
                                                Constants.DefaultCircuitLevelWindowParams
                                    }
                            )

                        tcs.SetResult circuitId
                    | _ ->
                        failwith
                            "Unexpected circuit state when receiving CreatedFast cell"
                | :? CellEncryptedRelay as enRelay ->
                    let streamId, relayData, fromNode = decryptCell enRelay

                    match relayData with
                    | RelayData.RelayData _ ->
                        fromNode.Window.DeliverDecrease()

                        if fromNode.Window.NeedSendme() then
                            do!
                                sendRelayCell
                                    Constants.DefaultStreamId
                                    RelayData.RelaySendMe
                                    (Some fromNode)
                    | RelayData.RelayExtended2 extended2 ->
                        match circuitState with
                        | Extending(circuitId, handshakeState, nodes, tcs) ->
                            let kdfResult =
                                handshakeState.GenerateKdfResult extended2

                            circuitState <-
                                Ready(
                                    circuitId,
                                    nodes
                                    @ List.singleton
                                        {
                                            TorCircuitNode.CryptoState =
                                                TorCryptoState.FromKdfResult
                                                    kdfResult
                                                    false
                                            Window =
                                                TorWindow
                                                    Constants.DefaultCircuitLevelWindowParams
                                        }
                                )

                            tcs.SetResult circuitId
                        | _ ->
                            failwith
                                "Unexpected circuit state when receiving Extended cell"
                    | RelayData.RelayEstablishedIntro _ ->
                        match circuitState with
                        | RegisteringAsIntroductionPoint
                            (
                                circuitId,
                                nodes,
                                privateKey,
                                publicKey,
                                tcs,
                                callback,
                                disconnectionCallback
                            ) ->
                            circuitState <-
                                ReadyAsIntroductionPoint(
                                    circuitId,
                                    nodes,
                                    privateKey,
                                    publicKey,
                                    callback,
                                    disconnectionCallback
                                )

                            tcs.SetResult()
                        | _ ->
                            failwith
                                "Unexpected circuit state when receiving ESTABLISHED_INTRO cell"
                    | RelayData.RelayEstablishedRendezvous ->
                        match circuitState with
                        | RegisteringAsRendezvousPoint(circuitId, nodes, tcs) ->
                            circuitState <-
                                ReadyAsRendezvousPoint(circuitId, nodes)

                            tcs.SetResult()
                        | _ ->
                            failwith
                                "Unexpected circuit state when receiving RENDEZVOUS_ESTABLISHED cell"
                    | RelaySendMe _ when streamId = Constants.DefaultStreamId ->
                        fromNode.Window.PackageIncrease()
                    | RelayIntroduce2 introduceMsg ->
                        match circuitState with
                        | ReadyAsIntroductionPoint
                            (
                                _, _, _, _, callback, _disconnectionCallback
                            ) -> do! callback introduceMsg
                        | _ ->
                            return
                                failwith
                                    "Received introduce2 cell over non-introduction-circuit huh?"
                    | RelayTruncated reason ->
                        match circuitState with
                        | CircuitState.Initialized
                        | Disconnected _ ->
                            // Circuit isn't created yet or was already dead!
                            ()
                        | Creating(circuitId, _, tcs)
                        | Extending(circuitId, _, _, tcs) ->
                            circuitState <- Truncated(circuitId, reason)

                            tcs.SetException(CircuitTruncatedException reason)
                        | WaitingForIntroduceAcknowledge(circuitId, _, tcs) ->
                            circuitState <- Truncated(circuitId, reason)

                            tcs.SetException(CircuitTruncatedException reason)
                        | RegisteringAsRendezvousPoint(circuitId, _, tcs)
                        | RegisteringAsIntroductionPoint
                            (
                                circuitId, _, _, _, tcs, _, _
                            )
                        | WaitingForRendezvousRequest
                            (
                                circuitId, _, _, _, _, _, tcs
                            ) ->
                            circuitState <- Truncated(circuitId, reason)

                            tcs.SetException(CircuitTruncatedException reason)
                        //FIXME: how can we tell the user that circuit is destroyed? if we throw here the listening thread with throw and user never finds out why
                        | Ready(circuitId, _)
                        | ReadyAsIntroductionPoint(circuitId, _, _, _, _, _)
                        | ReadyAsRendezvousPoint(circuitId, _)
                        // The circuit was already dead in our eyes, so we don't care about it being destroyed, just update the state to new destroyed state
                        | Destroyed(circuitId, _)
                        | Truncated(circuitId, _) ->
                            circuitState <- Truncated(circuitId, reason)
                            announceDeath()
                    | RelayData.RelayIntroduceAck ackMsg ->
                        match circuitState with
                        | WaitingForIntroduceAcknowledge(circuitId, nodes, tcs) ->
                            circuitState <- Ready(circuitId, nodes)

                            tcs.SetResult ackMsg
                        | _ ->
                            failwith
                                "Unexpected circuit state when receiving RelayIntroduceAck cell"
                    | RelayData.RelayRendezvous2 rendMsg ->
                        match circuitState with
                        | WaitingForRendezvousRequest
                            (
                                circuitId,
                                nodes,
                                clientRandomPrivateKey,
                                clientRandomPublicKey,
                                introAuthPublicKey,
                                introEncPublicKey,
                                tcs
                            ) ->

                            let serverPublicKey =
                                rendMsg.HandshakeData
                                |> Array.take Constants.KeyS256Length

                            let ntorKeySeed, mac =
                                HiddenServicesCipher.CalculateClientRendezvousKeys
                                    (X25519PublicKeyParameters(
                                        serverPublicKey,
                                        0
                                    ))
                                    clientRandomPublicKey
                                    clientRandomPrivateKey
                                    introAuthPublicKey
                                    introEncPublicKey

                            if mac
                               <> (rendMsg.HandshakeData
                                   |> Array.skip Constants.KeyS256Length
                                   |> Array.take Constants.Digest256Length) then
                                failwith "Invalid handshake data"


                            circuitState <-
                                Ready(
                                    circuitId,
                                    nodes
                                    @ List.singleton
                                        {
                                            TorCircuitNode.CryptoState =
                                                TorCryptoState.FromKdfResult
                                                    (Kdf.ComputeHSKdf
                                                        ntorKeySeed)
                                                    false
                                            Window =
                                                TorWindow
                                                    Constants.DefaultCircuitLevelWindowParams
                                        }
                                )

                            tcs.SetResult()
                        | _ ->
                            failwith
                                "Unexpected circuit state when receiving Rendevzous2 cell"
                    | RelayBegin beginRequest ->
                        if beginRequest.Address.Split(':').[0] = String.Empty
                           && serviceStreamCallback.IsSome then
                            do! serviceStreamCallback.Value streamId circuitObj
                    | _ -> ()

                    if streamId <> Constants.DefaultStreamId then
                        match (streamsMap.TryFind streamId, relayData) with
                        | (Some stream, _) ->
                            do! stream.HandleIncomingData relayData
                        | (None, RelayBegin _) -> ()
                        | (None, _) -> failwith "Unknown stream"
                | :? CellDestroy as destroyCell ->
                    match circuitState with
                    | CircuitState.Initialized
                    | Disconnected _ ->
                        // Circuit isn't created yet or is already dead!
                        ()
                    | Creating(circuitId, _, tcs)
                    | Extending(circuitId, _, _, tcs) ->

                        circuitState <- Destroyed(circuitId, destroyCell.Reason)

                        tcs.SetException(
                            CircuitDestroyedException destroyCell.Reason
                        )
                    | RegisteringAsRendezvousPoint(circuitId, _, tcs)
                    | RegisteringAsIntroductionPoint
                        (
                            circuitId, _, _, _, tcs, _, _
                        )
                    | WaitingForRendezvousRequest(circuitId, _, _, _, _, _, tcs) ->

                        circuitState <- Destroyed(circuitId, destroyCell.Reason)

                        tcs.SetException(
                            CircuitDestroyedException destroyCell.Reason
                        )
                    | WaitingForIntroduceAcknowledge(circuitId, _, tcs) ->
                        circuitState <- Destroyed(circuitId, destroyCell.Reason)

                        tcs.SetException(
                            CircuitDestroyedException destroyCell.Reason
                        )
                    //FIXME: how can we tell the user that circuit is destroyed? if we throw here the listening thread will throw and user never finds out why
                    | Ready(circuitId, _)
                    | ReadyAsIntroductionPoint(circuitId, _, _, _, _, _)
                    | ReadyAsRendezvousPoint(circuitId, _)
                    // The circuit was already dead in our eyes, so we don't care about it being destroyed, just update the state to new destroyed state
                    | Destroyed(circuitId, _)
                    | Truncated(circuitId, _) ->
                        circuitState <- Destroyed(circuitId, destroyCell.Reason)
                        announceDeath()
                | _ -> ()
            }

        let requestCreation circuitObj guardDetailOpt =
            async {
                match circuitState with
                | CircuitState.Initialized ->
                    let circuitId = guard.RegisterCircuit circuitObj
                    let connectionCompletionSource = TaskCompletionSource()

                    let handshakeState, handshakeCell =
                        match guardDetailOpt with
                        | FastCreate ->
                            let state = FastHandshake.Create() :> IHandshake

                            state,
                            {
                                CellCreateFast.X =
                                    state.GenerateClientMaterial()
                            }
                            :> ICell
                        | Create(_, onionKey, identityKey) ->
                            let state =
                                NTorHandshake.Create identityKey onionKey
                                :> IHandshake

                            state,
                            {
                                CellCreate2.HandshakeType = HandshakeType.NTor
                                HandshakeData = state.GenerateClientMaterial()
                            }
                            :> ICell

                    circuitState <-
                        Creating(
                            circuitId,
                            handshakeState,
                            connectionCompletionSource
                        )

                    do! guard.Send circuitId handshakeCell

                    TorLogger.Log(
                        sprintf
                            "TorCircuit[%i,%s]: sending create cell"
                            circuitId
                            circuitState.Name
                    )

                    return connectionCompletionSource.Task
                | _ -> return invalidOp "Circuit is already created"
            }

        let requestExtension nodeDetail =
            async {
                match circuitState with
                | CircuitState.Ready(circuitId, nodes) ->
                    match nodeDetail with
                    | FastCreate ->
                        return
                            invalidOp
                                "Only first hop can be created using CREATE_FAST"
                    | Create(address, onionKey, identityKey) ->
                        let connectionCompletionSource = TaskCompletionSource()

                        let handshakeState, handshakeCell =
                            let state =
                                NTorHandshake.Create identityKey onionKey
                                :> IHandshake

                            state,
                            {
                                RelayExtend2.LinkSpecifiers =
                                    [
                                        LinkSpecifier.CreateFromEndPoint address
                                        {
                                            LinkSpecifier.Type =
                                                LinkSpecifierType.LegacyIdentity
                                            Data = identityKey
                                        }
                                    ]
                                HandshakeType = HandshakeType.NTor
                                HandshakeData = state.GenerateClientMaterial()
                            }
                            |> RelayData.RelayExtend2

                        circuitState <-
                            Extending(
                                circuitId,
                                handshakeState,
                                nodes,
                                connectionCompletionSource
                            )

                        do!
                            internalSendRelayCell
                                Constants.DefaultStreamId
                                handshakeCell
                                None
                                true

                        return connectionCompletionSource.Task
                | _ ->
                    return
                        invalidOp
                            "Circuit is not in a state suitable for extending"
            }

        let registerAsIntroductionPoint
            authKeyPairOpt
            callback
            disconnectionCallback
            =
            async {
                match circuitState with
                | Ready(circuitId, nodes) ->
                    let lastNode = getCircuitLastNode()

                    let authPrivateKey, authPublicKey =
                        let authKeyPair =
                            match authKeyPairOpt with
                            | Some authKeyPair -> authKeyPair
                            | None ->
                                let kpGen = Ed25519KeyPairGenerator()
                                let random = SecureRandom()

                                kpGen.Init(
                                    Ed25519KeyGenerationParameters random
                                )

                                kpGen.GenerateKeyPair()

                        authKeyPair.Private :?> Ed25519PrivateKeyParameters,
                        authKeyPair.Public :?> Ed25519PublicKeyParameters

                    let establishIntroCell =
                        RelayEstablishIntro.Create
                            authPrivateKey
                            authPublicKey
                            lastNode.CryptoState.KeyHandshake
                        |> RelayData.RelayEstablishIntro

                    let connectionCompletionSource = TaskCompletionSource()

                    circuitState <-
                        CircuitState.RegisteringAsIntroductionPoint(
                            circuitId,
                            nodes,
                            authPrivateKey,
                            authPublicKey,
                            connectionCompletionSource,
                            callback,
                            disconnectionCallback
                        )

                    do!
                        internalSendRelayCell
                            Constants.DefaultStreamId
                            establishIntroCell
                            (Some lastNode)
                            false

                    return connectionCompletionSource.Task :> Task
                | _ ->
                    return
                        failwith
                            "Unexpected state for registering as introduction point"
            }

        let registerAsRendezvousPoint(cookie: array<byte>) =
            async {
                match circuitState with
                | Ready(circuitId, nodes) ->
                    let lastNode = getCircuitLastNode()

                    let establishRendezvousCell =
                        RelayData.RelayEstablishRendezvous cookie

                    let connectionCompletionSource = TaskCompletionSource()

                    circuitState <-
                        CircuitState.RegisteringAsRendezvousPoint(
                            circuitId,
                            nodes,
                            connectionCompletionSource
                        )

                    do!
                        internalSendRelayCell
                            Constants.DefaultStreamId
                            establishRendezvousCell
                            (Some lastNode)
                            false

                    return connectionCompletionSource.Task :> Task
                | _ ->
                    return
                        failwith
                            "Unexpected state for registering as rendezvous point"
            }

        let sendIntroduceRequest(introduceMsg: RelayIntroduce) =
            async {
                match circuitState with
                | Ready(circuitId, nodes) ->
                    let connectionCompletionSource =
                        TaskCompletionSource<RelayIntroduceAck>()

                    circuitState <-
                        WaitingForIntroduceAcknowledge(
                            circuitId,
                            nodes,
                            connectionCompletionSource
                        )

                    do!
                        internalSendRelayCell
                            0us
                            (RelayIntroduce1 introduceMsg)
                            None
                            false

                    return connectionCompletionSource.Task
                | _ ->
                    return
                        failwith "Unexpected state when sending introduce msg"
            }

        let waitForRendezvous
            (clientRandomPrivateKey: X25519PrivateKeyParameters)
            (clientRandomPublicKey: X25519PublicKeyParameters)
            (introAuthPublicKey: Ed25519PublicKeyParameters)
            (introEncPublicKey: X25519PublicKeyParameters)
            =
            async {
                match circuitState with
                | ReadyAsRendezvousPoint(circuitId, nodes) ->
                    let connectionCompletionSource = TaskCompletionSource()

                    circuitState <-
                        WaitingForRendezvousRequest(
                            circuitId,
                            nodes,
                            clientRandomPrivateKey,
                            clientRandomPublicKey,
                            introAuthPublicKey,
                            introEncPublicKey,
                            connectionCompletionSource
                        )

                    return connectionCompletionSource.Task :> Task
                | _ ->
                    return
                        failwith
                            "Unexpected state when waiting for rendezvous join"
            }

        let sendRendezvousCell
            (cookie: array<byte>)
            (clientRandomKey: X25519PublicKeyParameters)
            (introAuthPublicKey: Ed25519PublicKeyParameters)
            (introEncPrivateKey: X25519PrivateKeyParameters)
            (introEncPublicKey: X25519PublicKeyParameters)
            =
            async {
                match circuitState with
                | Ready(circuitId, nodes) ->
                    let serverPublicKey, serverPrivateKey =
                        let kpGenX = X25519KeyPairGenerator()
                        let random = SecureRandom()
                        kpGenX.Init(X25519KeyGenerationParameters random)
                        let keyPair = kpGenX.GenerateKeyPair()

                        keyPair.Public :?> X25519PublicKeyParameters,
                        keyPair.Private :?> X25519PrivateKeyParameters

                    let ntorKeySeed, mac =
                        HiddenServicesCipher.CalculateServerRendezvousKeys
                            clientRandomKey
                            serverPublicKey
                            serverPrivateKey
                            introAuthPublicKey
                            introEncPrivateKey
                            introEncPublicKey

                    let rendezvousCell =
                        {
                            RelayRendezvous.Cookie = cookie
                            HandshakeData =
                                Array.concat
                                    [ serverPublicKey.GetEncoded(); mac ]
                        }
                        |> RelayRendezvous1

                    (*
                        HACK: Currently, TorCircuit encrypts with forward and decrypts with backward because
                        we implemented it for client use only, this changes with introducing hidden service host
                        support.
                        HiddenServiceHost acts as a server and it should encrypt with Kb and decrypt Kf so we reverse
                        the ciphers/digests to accommodate this.
                    *)

                    circuitState <-
                        Ready(
                            circuitId,
                            nodes
                            @ List.singleton
                                {
                                    TorCircuitNode.CryptoState =
                                        TorCryptoState.FromKdfResult
                                            (Kdf.ComputeHSKdf ntorKeySeed)
                                            true
                                    Window =
                                        TorWindow
                                            Constants.DefaultCircuitLevelWindowParams
                                }
                        )

                    do!
                        internalSendRelayCell
                            0us
                            rendezvousCell
                            (List.tryLast nodes)
                            false
                | _ ->
                    return
                        failwith "Unexpected state when sending rendezvous msg"
            }

        async {
            let! cancelToken = Async.CancellationToken
            cancelToken.ThrowIfCancellationRequested()

            let! op = inbox.Receive()

            match op with
            | CircuitOperation.GetCircuitLastNode replyChannel ->
                TryExecuteAndReplyAsResult replyChannel getCircuitLastNode
            | CircuitOperation.SendRelayCell
                (
                    streamId, relayData, customDestinationOpt, replyChannel
                ) ->
                do!
                    sendRelayCell streamId relayData customDestinationOpt
                    |> TryExecuteAsyncAndReplyAsResult replyChannel
            | CircuitOperation.HandleIncomingCell
                (
                    circuitObj, cell, replyChannel
                ) ->
                do!
                    handleIncomingCell circuitObj cell
                    |> TryExecuteAsyncAndReplyAsResult replyChannel
            | CircuitOperation.Create(circuitObj, guardDetailOpt, replyChannel) ->
                do!
                    requestCreation circuitObj guardDetailOpt
                    |> TryExecuteAsyncAndReplyAsResult replyChannel
            | CircuitOperation.Extend(nodeDetail, replyChannel) ->
                do!
                    requestExtension nodeDetail
                    |> TryExecuteAsyncAndReplyAsResult replyChannel
            | CircuitOperation.RegisterAsIntroductionPoint
                (
                    authKeyPairOpt,
                    callback,
                    disconnectionCallback,
                    replyChannel
                ) ->
                do!
                    registerAsIntroductionPoint
                        authKeyPairOpt
                        callback
                        disconnectionCallback
                    |> TryExecuteAsyncAndReplyAsResult replyChannel
            | CircuitOperation.RegisterAsRendezvousPoint(cookie, replyChannel) ->
                do!
                    registerAsRendezvousPoint cookie
                    |> TryExecuteAsyncAndReplyAsResult replyChannel
            | CircuitOperation.SendIntroduceRequest(msg, replyChannel) ->
                do!
                    sendIntroduceRequest msg
                    |> TryExecuteAsyncAndReplyAsResult replyChannel
            | CircuitOperation.WaitForRendezvous
                (
                    clientRandomPrivateKey,
                    clientRandomPublicKey,
                    introAuthPublicKey,
                    introEncPublicKey,
                    replyChannel
                ) ->
                do!
                    waitForRendezvous
                        clientRandomPrivateKey
                        clientRandomPublicKey
                        introAuthPublicKey
                        introEncPublicKey
                    |> TryExecuteAsyncAndReplyAsResult replyChannel
            | CircuitOperation.SendRendezvousRequest
                (
                    cookie: array<byte>,
                    clientRandomKey,
                    introAuthPublicKey,
                    introEncPrivateKey,
                    introEncPublicKey,
                    replyChannel
                ) ->
                do!
                    sendRendezvousCell
                        cookie
                        clientRandomKey
                        introAuthPublicKey
                        introEncPrivateKey
                        introEncPublicKey
                    |> TryExecuteAsyncAndReplyAsResult replyChannel
            | CircuitOperation.HandleDeath -> announceDeath()

            return! CircuitMailBoxProcessor inbox
        }

    let circuitOperationsMailBox =
        MailboxProcessor.Start CircuitMailBoxProcessor

    //Client-only
    new(guard: TorGuard) = TorCircuit(guard, None)
    //Client-Server F# version
    new(guard: TorGuard,
        serviceStreamCallback: uint16 -> TorCircuit -> Async<unit>) =
        TorCircuit(guard, Some serviceStreamCallback)
    //Client-Server C# version
    new(guard: TorGuard, serviceStreamCallback: Func<uint16, TorCircuit, Task>) =
        let callback streamId circuit =
            async {
                return!
                    serviceStreamCallback.Invoke(streamId, circuit)
                    |> Async.AwaitTask
            }

        TorCircuit(guard, Some callback)

    member __.Id =
        match circuitState with
        | Creating(circuitId, _, _)
        | Extending(circuitId, _, _, _)
        | RegisteringAsIntroductionPoint(circuitId, _, _, _, _, _, _)
        | RegisteringAsRendezvousPoint(circuitId, _, _)
        | WaitingForIntroduceAcknowledge(circuitId, _, _)
        | WaitingForRendezvousRequest(circuitId, _, _, _, _, _, _)
        | Ready(circuitId, _)
        | ReadyAsIntroductionPoint(circuitId, _, _, _, _, _)
        | ReadyAsRendezvousPoint(circuitId, _)
        | Destroyed(circuitId, _)
        | Truncated(circuitId, _)
        | Disconnected circuitId -> circuitId
        | CircuitState.Initialized ->
            failwith
                "Should not happen: can't get circuitId for non-initialized circuit."

    member __.GetLastNode() =
        async {
            let! lastNodeResult =
                circuitOperationsMailBox.PostAndAsyncReply
                    CircuitOperation.GetCircuitLastNode

            return UnwrapResult lastNodeResult
        }

    member __.SendRelayCell
        (streamId: uint16)
        (relayData: RelayData)
        (customDestinationOpt: Option<TorCircuitNode>)
        =
        async {
            let! sendResult =
                circuitOperationsMailBox.PostAndAsyncReply(fun replyChannel ->
                    CircuitOperation.SendRelayCell(
                        streamId,
                        relayData,
                        customDestinationOpt,
                        replyChannel
                    )
                )

            return UnwrapResult sendResult
        }

    member self.Create(guardDetailOpt: CircuitNodeDetail) =
        async {
            let! completionTaskRes =
                circuitOperationsMailBox.PostAndAsyncReply(
                    (fun replyChannel ->
                        CircuitOperation.Create(
                            self,
                            guardDetailOpt,
                            replyChannel
                        )
                    ),
                    Constants.CircuitOperationTimeout.TotalMilliseconds |> int
                )

            return!
                completionTaskRes
                |> UnwrapResult
                |> Async.AwaitTask
                |> FSharpUtil.WithTimeout Constants.CircuitOperationTimeout
        }

    member __.Extend(nodeDetail: CircuitNodeDetail) =
        async {
            let! completionTaskRes =
                circuitOperationsMailBox.PostAndAsyncReply(
                    (fun replyChannel ->
                        CircuitOperation.Extend(nodeDetail, replyChannel)
                    ),
                    Constants.CircuitOperationTimeout.TotalMilliseconds |> int
                )

            return!
                completionTaskRes
                |> UnwrapResult
                |> Async.AwaitTask
                |> FSharpUtil.WithTimeout Constants.CircuitOperationTimeout
        }

    member __.RegisterAsIntroductionPoint
        (authKeyPairOpt: Option<AsymmetricCipherKeyPair>)
        callback
        disconnectionCallback
        =
        async {
            let! completionTaskRes =
                circuitOperationsMailBox.PostAndAsyncReply(
                    (fun replyChannel ->
                        CircuitOperation.RegisterAsIntroductionPoint(
                            authKeyPairOpt,
                            callback,
                            disconnectionCallback,
                            replyChannel
                        )
                    ),
                    Constants.CircuitOperationTimeout.TotalMilliseconds |> int
                )

            return!
                completionTaskRes
                |> UnwrapResult
                |> Async.AwaitTask
                |> FSharpUtil.WithTimeout Constants.CircuitOperationTimeout
        }

    member __.RegisterAsRendezvousPoint(cookie: array<byte>) =
        async {
            let! completionTaskRes =
                circuitOperationsMailBox.PostAndAsyncReply(
                    (fun replyChannel ->
                        CircuitOperation.RegisterAsRendezvousPoint(
                            cookie,
                            replyChannel
                        )
                    ),
                    Constants.CircuitOperationTimeout.TotalMilliseconds |> int
                )


            return!
                completionTaskRes
                |> UnwrapResult
                |> Async.AwaitTask
                |> FSharpUtil.WithTimeout Constants.CircuitOperationTimeout
        }

    member self.ExtendAsync nodeDetail =
        self.Extend nodeDetail |> Async.StartAsTask

    member self.CreateAsync guardDetailOpt =
        self.Create guardDetailOpt |> Async.StartAsTask

    member __.Introduce(introduceMsg: RelayIntroduce) =
        async {
            let! completionTaskRes =
                circuitOperationsMailBox.PostAndAsyncReply(
                    (fun replyChannel ->
                        CircuitOperation.SendIntroduceRequest(
                            introduceMsg,
                            replyChannel
                        )
                    ),
                    Constants.CircuitOperationTimeout.TotalMilliseconds |> int
                )

            return!
                completionTaskRes
                |> UnwrapResult
                |> Async.AwaitTask
                |> FSharpUtil.WithTimeout Constants.CircuitOperationTimeout
        }

    member __.WaitingForRendezvousJoin
        (clientRandomPrivateKey: X25519PrivateKeyParameters)
        (clientRandomPublicKey: X25519PublicKeyParameters)
        (introAuthPublicKey: Ed25519PublicKeyParameters)
        (introEncPublicKey: X25519PublicKeyParameters)
        =
        async {
            let! completionTaskRes =
                circuitOperationsMailBox.PostAndAsyncReply(
                    (fun replyChannel ->
                        CircuitOperation.WaitForRendezvous(
                            clientRandomPrivateKey,
                            clientRandomPublicKey,
                            introAuthPublicKey,
                            introEncPublicKey,
                            replyChannel
                        )
                    ),
                    Constants.CircuitRendezvousTimeout.TotalMilliseconds |> int
                )

            return!
                completionTaskRes
                |> UnwrapResult
                |> Async.AwaitTask
                |> FSharpUtil.WithTimeout Constants.CircuitRendezvousTimeout

        }

    member __.Rendezvous
        (cookie: array<byte>)
        (clientRandomKey: X25519PublicKeyParameters)
        (introAuthPublicKey: Ed25519PublicKeyParameters)
        (introEncPrivateKey: X25519PrivateKeyParameters)
        (introEncPublicKey: X25519PublicKeyParameters)
        =

        async {
            let! completionRes =
                circuitOperationsMailBox.PostAndAsyncReply(
                    (fun replyChannel ->
                        CircuitOperation.SendRendezvousRequest(
                            cookie,
                            clientRandomKey,
                            introAuthPublicKey,
                            introEncPrivateKey,
                            introEncPublicKey,
                            replyChannel
                        )
                    ),
                    Constants.CircuitOperationTimeout.TotalMilliseconds |> int
                )

            return UnwrapResult completionRes
        }

    member self.RegisterAsIntroductionPointAsync
        (authKeyPairOpt: Option<AsymmetricCipherKeyPair>)
        (callback: Func<RelayIntroduce, Task>)
        (disconnectCallback: Action)
        =
        let introduceCallback =
            fun relayIntroduce ->
                async {
                    return! callback.Invoke relayIntroduce |> Async.AwaitTask
                }

        let disconnectCallback = fun () -> disconnectCallback.Invoke()

        self.RegisterAsIntroductionPoint
            authKeyPairOpt
            introduceCallback
            disconnectCallback
        |> Async.StartAsTask

    member self.RegisterAsRendezvousPointAsync(cookie: array<byte>) =
        self.RegisterAsRendezvousPoint cookie |> Async.StartAsTask

    member internal __.RegisterStream
        (stream: ITorStream)
        (idOpt: Option<uint16>)
        : uint16 =
        let safeRegister() =
            match idOpt with
            | Some id ->
                streamsMap <- streamsMap.Add(id, stream)
                id
            | None ->
                let newId = uint16 streamsCount
                streamsCount <- streamsCount + 1
                streamsMap <- streamsMap.Add(newId, stream)
                newId

        lock streamSetupLock safeRegister

    interface ITorCircuit with
        member self.HandleDestroyedGuard() =
            circuitOperationsMailBox.Post CircuitOperation.HandleDeath

        member self.HandleIncomingCell(cell: ICell) =
            async {
                //FIXME: add exception handling to mailbox and remove reply from here?
                let! handleRes =
                    circuitOperationsMailBox.PostAndAsyncReply(fun replyChannel ->
                        CircuitOperation.HandleIncomingCell(
                            self,
                            cell,
                            replyChannel
                        )
                    )

                return UnwrapResult handleRes
            }
