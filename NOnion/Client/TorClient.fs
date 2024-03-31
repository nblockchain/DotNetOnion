namespace NOnion.Client

open System
open System.Collections.Concurrent
open System.IO
open System.Net
open System.Net.Http
open System.Text.RegularExpressions

open NOnion.Directory
open NOnion.Utility
open NOnion
open NOnion.Network

type CircuitPurpose =
    | Unknown
    | Exit

type TorClient internal (directory: TorDirectory) =
    static let maximumBootstrapTries = 5

    static let maximumExtendByNodeRetry = 5

    static let ConvertFallbackIncToList(fallbackIncString: string) =
        let ipv4Pattern = "\"([0-9\\.]+)\\sorport=(\\S*)\\sid=(\\S*)\""
        let matches = Regex.Matches(fallbackIncString, ipv4Pattern)

        matches
        |> Seq.cast
        |> Seq.map(fun (regMatch: Match) ->
            regMatch.Groups.[1].Value, int regMatch.Groups.[2].Value
        )
        |> Seq.toList

    static let SelectRandomEndpoints(fallbackList: List<string * int>) =
        fallbackList
        |> SeqUtils.TakeRandom maximumBootstrapTries
        |> Seq.map(fun (ipString, port) ->
            let ipAddress = IPAddress.Parse ipString
            IPEndPoint(ipAddress, port)
        )
        |> Seq.toList

    static let BootstrapDirectory
        (cachePath: Option<DirectoryInfo>)
        (ipEndPointList: List<IPEndPoint>)
        =
        async {
            let rec tryBootstrap(ipEndPointList: List<IPEndPoint>) =
                async {
                    match ipEndPointList with
                    | ipEndPoint :: tail ->
                        try
                            let cacheDirectory =
                                match cachePath with
                                | None ->
                                    let tempDir =
                                        DirectoryInfo(
                                            Path.Combine(
                                                Path.GetTempPath(),
                                                Path.GetFileNameWithoutExtension(
                                                    Path.GetRandomFileName()
                                                )
                                            )
                                        )

                                    tempDir.Create()
                                    tempDir
                                | Some path -> path

                            let! directory =
                                TorDirectory.Bootstrap ipEndPoint cacheDirectory

                            return directory
                        with
                        | :? NOnionException -> return! tryBootstrap tail
                    | [] -> return failwith "Maximum bootstrap tries reached!"
                }

            return! tryBootstrap ipEndPointList
        }

    static let CreateClientFromFallbackString
        (fallbackListString: string)
        (cachePath: Option<DirectoryInfo>)
        =
        async {
            let! directory =
                fallbackListString
                |> ConvertFallbackIncToList
                |> SelectRandomEndpoints
                |> BootstrapDirectory cachePath

            return new TorClient(directory)
        }

    let guardsToDispose = ConcurrentBag<TorGuard>()

    static member AsyncBootstrapWithEmbeddedList
        (cachePath: Option<DirectoryInfo>)
        =
        async {
            let fallbackListString =
                EmbeddedResourceUtility.ExtractEmbeddedResourceFileContents(
                    "fallback_dirs.inc"
                )

            return! CreateClientFromFallbackString fallbackListString cachePath
        }

    static member BootstrapWithEmbeddedListAsync
        (cachePath: Option<DirectoryInfo>)
        =
        TorClient.AsyncBootstrapWithEmbeddedList cachePath |> Async.StartAsTask

    static member AsyncBootstrapWithGitlab(cachePath: Option<DirectoryInfo>) =
        async {
            // Don't put this inside the fallbackListString or it gets disposed
            // before the task gets executed
            use httpClient = new HttpClient()

            let! fallbackListString =
                let urlToTorServerList =
                    "https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/app/config/fallback_dirs.inc"

                httpClient.GetStringAsync urlToTorServerList |> Async.AwaitTask

            return! CreateClientFromFallbackString fallbackListString cachePath
        }

    static member BootstrapWithGitlabAsync(cachePath: Option<DirectoryInfo>) =
        TorClient.AsyncBootstrapWithGitlab cachePath |> Async.StartAsTask

    member __.Directory = directory

    member internal __.AsyncCreateCircuitWithCallback
        (hopsCount: int)
        (purpose: CircuitPurpose)
        (extendByNodeOpt: Option<CircuitNodeDetail>)
        (serviceStream: uint16 -> TorCircuit -> Async<unit>)
        =
        async {
            let rec createNewGuard() =
                async {
                    let! ipEndPoint, nodeDetail =
                        directory.GetRouter RouterType.Guard

                    try
                        let! guard =
                            TorGuard.NewClientWithIdentity
                                ipEndPoint
                                (nodeDetail.GetIdentityKey() |> Some)

                        guardsToDispose.Add guard
                        return guard, nodeDetail
                    with
                    | :? GuardConnectionFailedException ->
                        return! createNewGuard()
                }

            let rec tryCreateCircuit(tryNumber: int) =
                async {
                    if tryNumber > maximumExtendByNodeRetry then
                        return raise <| DestinationNodeCantBeReachedException()
                    else
                        try
                            let! guard, guardDetail = createNewGuard()
                            let circuit = TorCircuit(guard, serviceStream)

                            do!
                                circuit.Create guardDetail
                                |> Async.Ignore<uint16>

                            let rec extend
                                (numHopsToExtend: int)
                                (nodesSoFar: List<CircuitNodeDetail>)
                                =
                                async {
                                    if numHopsToExtend > 0 then
                                        let rec findUnusedNode() =
                                            async {
                                                let! _ipEndPoint, nodeDetail =
                                                    if numHopsToExtend = 1 then
                                                        match purpose with
                                                        | Unknown ->
                                                            directory.GetRouter
                                                                RouterType.Normal
                                                        | Exit ->
                                                            directory.GetRouter
                                                                RouterType.Exit
                                                    else
                                                        directory.GetRouter
                                                            RouterType.Normal

                                                if (List.contains
                                                        nodeDetail
                                                        nodesSoFar) then
                                                    return! findUnusedNode()
                                                else
                                                    return nodeDetail
                                            }

                                        let! newUnusedNode = findUnusedNode()

                                        do!
                                            circuit.Extend newUnusedNode
                                            |> Async.Ignore<uint16>

                                        return!
                                            extend
                                                (numHopsToExtend - 1)
                                                (newUnusedNode :: nodesSoFar)
                                    else
                                        ()
                                }

                            do!
                                extend
                                    (hopsCount - 1)
                                    (List.singleton guardDetail)

                            match extendByNodeOpt with
                            | Some extendByNode ->
                                try
                                    do!
                                        circuit.Extend extendByNode
                                        |> Async.Ignore<uint16>
                                with
                                | :? NOnionException ->
                                    return
                                        raise
                                        <| DestinationNodeCantBeReachedException
                                            ()
                            | None -> ()

                            return circuit
                        with
                        | :? DestinationNodeCantBeReachedException ->
                            return! tryCreateCircuit(tryNumber + 1)
                        | ex ->
                            match FSharpUtil.FindException<NOnionException> ex
                                with
                            | Some _nonionEx ->
                                return! tryCreateCircuit tryNumber
                            | None -> return raise <| FSharpUtil.ReRaise ex
                }

            let startTryNumber = 1

            return! tryCreateCircuit startTryNumber
        }

    member self.AsyncCreateCircuit
        (hopsCount: int)
        (purpose: CircuitPurpose)
        (extendByNodeOpt: Option<CircuitNodeDetail>)
        =
        let noop _ _ =
            async { return () }

        self.AsyncCreateCircuitWithCallback
            hopsCount
            purpose
            extendByNodeOpt
            noop

    member self.CreateCircuitAsync
        (
            hopsCount: int,
            purpose: CircuitPurpose,
            extendByNode: Option<CircuitNodeDetail>
        ) =
        self.AsyncCreateCircuit hopsCount purpose extendByNode
        |> Async.StartAsTask


    interface IDisposable with
        member __.Dispose() =
            for guard in guardsToDispose do
                (guard :> IDisposable).Dispose()
