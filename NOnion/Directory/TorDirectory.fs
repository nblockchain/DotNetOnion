namespace NOnion.Directory

open System
open System.IO
open System.Net
open System.Text

open Newtonsoft.Json

open NOnion
open NOnion.Crypto
open NOnion.Network
open NOnion.Http
open NOnion.Utility
open NOnion.Utility.ByteArrayUtil

type RouterType =
    | Normal
    | Guard
    | Directory
    | Exit

type TorDirectory =
    private
        {
            mutable NetworkStatus: NetworkStatusDocument
            mutable ServerDescriptors: Map<string, MicroDescriptorEntry>
        }

    member private self.IsLive() =
        self.NetworkStatus.IsLive()

    member private self.GetRandomDirectorySource() =
        let directorySourceOpt =
            self.NetworkStatus.Routers
            |> Seq.filter(fun elem ->
                elem.DirectoryPort.IsSome && elem.DirectoryPort.Value <> 0
            )
            |> SeqUtils.TakeRandom 1
            |> Seq.tryHead

        match directorySourceOpt with
        | Some directorySource -> directorySource
        | None ->
            failwith
                "TorDirectory::GetRandomDirectorySource: couldn't find suitable directory source."

    member self.GetMicroDescriptorByIdentity
        (identity: string)
        : Async<MicroDescriptorEntry> =
        async {
            let! networkStatus = self.GetLiveNetworkStatus()

            let routerConsensusEntryOpt =
                networkStatus.Routers
                |> List.tryFind(fun router -> router.Identity.Value = identity)

            match routerConsensusEntryOpt with
            | None ->
                return
                    failwith
                        "TorDirectory::GetMicroDescriptorByIdentity: router was not in the latest consensus"
            | Some routerConsensusEntry ->
                if self.ServerDescriptors
                   |> Map.containsKey
                       routerConsensusEntry.MicroDescriptorDigest.Value then
                    return
                        self.ServerDescriptors.[routerConsensusEntry.MicroDescriptorDigest.Value]
                else
                    let directoryRouter = self.GetRandomDirectorySource()

                    use! guard =
                        TorGuard.NewClient(
                            IPEndPoint(
                                IPAddress.Parse(directoryRouter.IP.Value),
                                directoryRouter.OnionRouterPort.Value
                            )
                        )

                    let circuit = TorCircuit(guard)
                    use stream = new TorStream(circuit)

                    (*
                        * We always use FastCreate authentication because privacy is not important for mono-hop
                        * directory browsing, this removes the need of checking descriptors and making sure they
                        * are no more than one week old (according to spec, routers must accept outdated keys
                        * until 1 week after key update).
                        *)
                    do!
                        circuit.Create CircuitNodeDetail.FastCreate
                        |> Async.Ignore

                    do! stream.ConnectToDirectory() |> Async.Ignore

                    let httpClient =
                        TorHttpClient(stream, directoryRouter.IP.Value)

                    let! response =
                        httpClient.GetAsString
                            (sprintf
                                "/tor/micro/d/%s"
                                routerConsensusEntry.MicroDescriptorDigest.Value)
                            false

                    let parsedDescriptorOpt =
                        MicroDescriptorEntry.ParseMany response
                        |> Seq.tryExactlyOne

                    match parsedDescriptorOpt with
                    | None ->
                        return
                            failwith
                                "BUG: can't get microdescriptor, Parse returned no item or more than one"
                    | Some parsedDescriptor ->
                        self.ServerDescriptors <-
                            self.ServerDescriptors
                            |> Map.add
                                routerConsensusEntry.MicroDescriptorDigest.Value
                                parsedDescriptor

                        return parsedDescriptor
        }

    member private self.GetRouterDetailByIdentity(identity: string) =
        async {
            let! networkStatus = self.GetLiveNetworkStatus()

            let routerEntryOpt =
                networkStatus.Routers
                |> List.tryFind(fun router -> router.Identity.Value = identity)

            match routerEntryOpt with
            | None ->
                return
                    failwith
                        "TorDirectory::GetRouterDetailByIdentity: router was not in the latest consensus"
            | Some routerEntry ->
                let! descriptor = self.GetMicroDescriptorByIdentity identity

                let fingerprintBytes =
                    Base64Util.FromString(routerEntry.GetIdentity())

                let nTorOnionKeyBytes =
                    Base64Util.FromString(descriptor.NTorOnionKey.Value)

                let endpoint =
                    IPEndPoint(
                        IPAddress.Parse(routerEntry.IP.Value),
                        routerEntry.OnionRouterPort.Value
                    )

                return
                    endpoint,
                    CircuitNodeDetail.Create(
                        endpoint,
                        nTorOnionKeyBytes,
                        fingerprintBytes
                    )
        }


    member self.GetRouter(filter: RouterType) =
        async {
            do! self.UpdateConsensusIfNotLive()

            let randomServerOpt =
                self.NetworkStatus.Routers
                |> match filter with
                   | Normal -> Seq.ofList
                   | Directory ->
                       Seq.filter(fun router ->
                           router.DirectoryPort.IsSome
                           && router.DirectoryPort.Value > 0
                       )
                   | Guard ->
                       Seq.filter(fun router ->
                           Seq.contains "Guard" router.Flags
                       )
                   | Exit ->
                       Seq.filter(fun router -> Seq.contains "Exit" router.Flags
                       )
                |> SeqUtils.TakeRandom 1
                |> Seq.tryHead

            match randomServerOpt with
            | Some randomServer ->
                return!
                    randomServer.GetIdentity() |> self.GetRouterDetailByIdentity
            | None -> return failwith "Couldn't find suitable router"
        }

    member self.GetRouterAsync(filter: RouterType) =
        self.GetRouter filter |> Async.StartAsTask

    member self.GetCircuitNodeDetailByIdentity(identity: string) =
        async {
            let! _endpoint, circuitNodeDetail =
                self.GetRouterDetailByIdentity identity

            return circuitNodeDetail
        }

    member private self.UpdateConsensusIfNotLive() =
        async {
            if self.IsLive() then
                TorLogger.Log
                    "TorDirectory: no need to get the consensus document"

                return ()
            else
                TorLogger.Log "TorDirectory: Updating consensus document..."

                let directoryRouter = self.GetRandomDirectorySource()

                use! guard =
                    TorGuard.NewClient(
                        IPEndPoint(
                            IPAddress.Parse(directoryRouter.IP.Value),
                            directoryRouter.OnionRouterPort.Value
                        )
                    )

                let circuit = TorCircuit(guard)
                use stream = new TorStream(circuit)

                (*
                 * We always use FastCreate authentication because privacy is not important for mono-hop
                 * directory browsing, this removes the need of checking descriptors and making sure they
                 * are no more than one week old (according to spec, routers must accept outdated keys
                 * until 1 week after key update).
                 *)
                do! circuit.Create CircuitNodeDetail.FastCreate |> Async.Ignore

                do! stream.ConnectToDirectory() |> Async.Ignore

                let httpClient = TorHttpClient(stream, directoryRouter.IP.Value)

                let! response =
                    httpClient.GetAsString
                        "/tor/status-vote/current/consensus-microdesc"
                        false

                self.NetworkStatus <- NetworkStatusDocument.Parse response
        }

    static member BootstrapWithGuard
        (guard: TorGuard)
        (cacheDirectory: DirectoryInfo)
        =
        async {
            let! networkStatus =
                let downloadConsensus(consensusPathOpt: Option<string>) =
                    async {
                        let circuit = TorCircuit guard

                        do!
                            circuit.Create CircuitNodeDetail.FastCreate
                            |> Async.Ignore

                        use consensusStream = new TorStream(circuit)
                        do! consensusStream.ConnectToDirectory() |> Async.Ignore

                        let consensusHttpClient =
                            TorHttpClient(
                                consensusStream,
                                Constants.DefaultHttpHost
                            )

                        let! consensusStr =
                            consensusHttpClient.GetAsString
                                "/tor/status-vote/current/consensus-microdesc"
                                false

                        match consensusPathOpt with
                        | Some consensusPath ->
                            File.WriteAllText(consensusPath, consensusStr)
                        | None -> ()

                        return NetworkStatusDocument.Parse consensusStr
                    }

                async {
                    if isNull cacheDirectory then
                        return! downloadConsensus None
                    else
                        let consensusPath =
                            Path.Combine(
                                cacheDirectory.FullName,
                                "consensus.txt"
                            )

                        if File.Exists consensusPath then
                            let maybeLiveNetworkStatus =
                                File.ReadAllText consensusPath
                                |> NetworkStatusDocument.Parse

                            if maybeLiveNetworkStatus.IsLive() then
                                return maybeLiveNetworkStatus
                            else
                                return! downloadConsensus(Some consensusPath)
                        else
                            return! downloadConsensus(Some consensusPath)
                }

            let stillValidOldDescriptors =
                if isNull cacheDirectory then
                    List.empty<string * MicroDescriptorEntry>
                else
                    let consensusPath =
                        Path.Combine(cacheDirectory.FullName, "descriptor.json")

                    if File.Exists consensusPath then
                        let oldDescriptorCache =
                            File.ReadAllText consensusPath
                            |> JsonConvert.DeserializeObject<List<string * MicroDescriptorEntry>>

                        oldDescriptorCache
                        |> List.filter(fun (digest, _) ->
                            networkStatus.Routers
                            |> List.exists(fun router ->
                                router.MicroDescriptorDigest.Value = digest
                            )
                        )
                    else
                        List.empty<string * MicroDescriptorEntry>

            let descriptorsToDownload =
                networkStatus.Routers
                |> Seq.choose(fun router -> router.MicroDescriptorDigest)
                |> Seq.except(
                    stillValidOldDescriptors
                    |> Seq.map(fun (digest, _) -> digest)
                )

            let! downloadResults =
                async {
                    if Seq.length descriptorsToDownload > 0 then
                        let circuit = TorCircuit guard

                        do!
                            circuit.Create CircuitNodeDetail.FastCreate
                            |> Async.Ignore

                        let downloadDescriptorsForChunk
                            (digestsChunk: array<string>)
                            =
                            async {
                                use descriptorsStream = new TorStream(circuit)

                                do!
                                    descriptorsStream.ConnectToDirectory()
                                    |> Async.Ignore

                                let descriptorsHttpClient =
                                    TorHttpClient(
                                        descriptorsStream,
                                        Constants.DefaultHttpHost
                                    )

                                let! descriptorsStr =
                                    descriptorsHttpClient.GetAsString
                                        (sprintf
                                            "/tor/micro/d/%s"
                                            (String.concat "-" digestsChunk))
                                        false

                                let trimmedDescriptors =
                                    descriptorsStr.TrimEnd('\n')

                                return
                                    MicroDescriptorEntry.ParseMany
                                        trimmedDescriptors
                                    |> List.map(fun descriptor ->
                                        descriptor.Digest.Value, descriptor
                                    )
                            }

                        let chunkedJobs =
                            descriptorsToDownload
                            |> Seq.chunkBySize 96
                            |> Seq.map downloadDescriptorsForChunk

                        let! chunkedResults = Async.Parallel(chunkedJobs, 16)

                        return List.concat chunkedResults

                    else
                        return List.empty<string * MicroDescriptorEntry>
                }

            let allResults =
                List.append downloadResults stillValidOldDescriptors

            if not(isNull cacheDirectory) then
                let jsonRep = JsonConvert.SerializeObject allResults

                File.WriteAllText(
                    Path.Combine(cacheDirectory.FullName, "descriptor.json"),
                    jsonRep
                )

            let descriptorsMap = allResults |> Map.ofList

            return
                {
                    TorDirectory.NetworkStatus = networkStatus
                    ServerDescriptors = descriptorsMap
                }
        }


    static member Bootstrap
        (nodeEndPoint: IPEndPoint)
        (cacheDirectory: DirectoryInfo)
        =
        async {
            use! guard = TorGuard.NewClient nodeEndPoint
            return! TorDirectory.BootstrapWithGuard guard cacheDirectory
        }

    member self.GetLiveNetworkStatus() =
        async {
            do! self.UpdateConsensusIfNotLive()
            return self.NetworkStatus
        }

    member self.TryGetDescriptorByIdentityFromCache(b64Identity: string) =
        let routerEntryOpt =
            self.NetworkStatus.Routers
            |> List.tryFind(fun router -> router.Identity.Value = b64Identity)

        match routerEntryOpt with
        | None -> None
        | Some routerEntry ->
            self.ServerDescriptors
            |> Map.tryFind routerEntry.MicroDescriptorDigest.Value

    static member BootstrapAsync
        (
            nodeEndPoint: IPEndPoint,
            cacheDirectory: DirectoryInfo
        ) =
        TorDirectory.Bootstrap nodeEndPoint cacheDirectory |> Async.StartAsTask

    static member BootstrapWithGuardAsync
        (
            guard: TorGuard,
            cacheDirectory: DirectoryInfo
        ) =
        TorDirectory.BootstrapWithGuard guard cacheDirectory
        |> Async.StartAsTask

    member self.GetResponsibleHiddenServiceDirectories
        (blindedPublicKey: array<byte>)
        (sharedRandomValue: string)
        (periodNumber: uint64)
        (periodLength: uint64)
        (directoriesToAdd: int)
        =
        async {

            let! networkStatus = self.GetLiveNetworkStatus()

            let directories =
                networkStatus.GetHiddenServiceDirectories()
                |> List.choose(fun node ->
                    let identity = node.GetIdentity()

                    self.TryGetDescriptorByIdentityFromCache identity
                    |> Option.bind(fun node -> node.Ed25519Identity)
                    |> Option.map(fun ed25519Identity ->
                        identity,
                        Array.concat
                            [
                                "node-idx" |> Encoding.ASCII.GetBytes
                                ed25519Identity |> Base64Util.FromString
                                sharedRandomValue |> Convert.FromBase64String
                                periodNumber
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                periodLength
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                            ]
                        |> HiddenServicesCipher.SHA3256
                    )
                )
                |> List.sortWith(fun (_, idx1) (_, idx2) ->
                    ByteArrayCompare idx1 idx2
                )

            let rec getRoutersToFetch (replicaNum: int) (state: list<string>) =
                if replicaNum > Constants.HiddenServices.Hashring.ReplicasNum then
                    state
                else
                    let hsIndex =
                        Array.concat
                            [
                                "store-at-idx" |> Encoding.ASCII.GetBytes
                                blindedPublicKey
                                replicaNum
                                |> uint64
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                periodLength
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                                periodNumber
                                |> IntegerSerialization.FromUInt64ToBigEndianByteArray
                            ]
                        |> HiddenServicesCipher.SHA3256

                    let start =
                        let maybeStart =
                            let hsIndexes =
                                directories
                                |> Array.ofList
                                |> Array.map(fun (_, hsIndex) -> hsIndex)

                            Array.BinarySearch(
                                hsIndexes,
                                hsIndex,
                                ByteArrayComparer()
                            )

                        if maybeStart < 0 then
                            let complement = ~~~maybeStart

                            // Getting the length of the list if no member is greater than the key we
                            // are looking for so start at the first element.
                            if complement >= directories.Length then
                                let arrayStartIndex = 0
                                arrayStartIndex
                            else
                                complement
                        else
                            maybeStart

                    let rec pickNodes startIndex nToAdd state =
                        if nToAdd = 0 then
                            state
                        else
                            let node = fst directories.[startIndex]

                            let nextIndex =
                                let idx = startIndex + 1

                                if idx = directories.Length then
                                    0
                                else
                                    idx

                            if not(state |> Seq.contains node) then
                                if nextIndex = start then
                                    node :: state
                                else
                                    pickNodes
                                        nextIndex
                                        (nToAdd - 1)
                                        (node :: state)
                            else if nextIndex = start then
                                state
                            else
                                pickNodes nextIndex nToAdd state

                    getRoutersToFetch
                        (replicaNum + 1)
                        (pickNodes start directoriesToAdd state)

            return getRoutersToFetch 1 List.empty
        }
