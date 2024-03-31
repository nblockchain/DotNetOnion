namespace NOnion.Proxy

open FSharpx.Collections
open System
open System.IO
open System.Net
open System.Net.Sockets
open System.Text
open System.Threading

open NOnion
open NOnion.Client
open NOnion.Network
open NOnion.Services

type TorProxy private (listener: TcpListener, torClient: TorClient) =
    let mutable lastActiveCircuitOpt: Option<TorCircuit> = None

    let handleConnection(client: TcpClient) =
        async {
            let! cancelToken = Async.CancellationToken
            cancelToken.ThrowIfCancellationRequested()

            let stream = client.GetStream()

            let readHeaders() =
                async {
                    let stringBuilder = StringBuilder()
                    // minimum request 16 bytes: GET / HTTP/1.1\r\n\r\n
                    let preReadLen = 18
                    let! buffer = stream.AsyncRead preReadLen

                    buffer
                    |> Encoding.ASCII.GetString
                    |> stringBuilder.Append
                    |> ignore<StringBuilder>

                    let rec innerReadRest() =
                        async {
                            if stringBuilder.ToString().EndsWith("\r\n\r\n") then
                                return ()
                            else
                                let! newByte = stream.AsyncRead 1

                                newByte
                                |> Encoding.ASCII.GetString
                                |> stringBuilder.Append
                                |> ignore<StringBuilder>

                                return! innerReadRest()
                        }

                    do! innerReadRest()

                    return stringBuilder.ToString()
                }

            let! headers = readHeaders()

            let headerLines =
                headers.Split(
                    [| "\r\n" |],
                    StringSplitOptions.RemoveEmptyEntries
                )

            match Seq.tryHeadTail headerLines with
            | Some(firstLine, restOfHeaders) ->
                let firstLineParts = firstLine.Split(' ')

                let method = firstLineParts.[0]
                let url = firstLineParts.[1]
                let protocolVersion = firstLineParts.[2]

                if protocolVersion <> "HTTP/1.1" then
                    return failwith "TorProxy: protocol version mismatch"

                let rec copySourceToDestination
                    (source: Stream)
                    (dest: Stream)
                    =
                    async {
                        do! source.CopyToAsync dest |> Async.AwaitTask

                        // CopyToAsync returns when source is closed so we can close dest
                        dest.Close()
                    }

                let createStreamToDestination(parsedUrl: Uri) =
                    async {
                        if parsedUrl.DnsSafeHost.EndsWith(".onion") then
                            let! client =
                                TorServiceClient.Connect
                                    torClient
                                    (sprintf
                                        "%s:%i"
                                        parsedUrl.DnsSafeHost
                                        parsedUrl.Port)

                            return! client.GetStream()
                        else
                            let! circuit =
                                match lastActiveCircuitOpt with
                                | Some lastActiveCircuit when
                                    lastActiveCircuit.IsActive
                                    ->
                                    async {
                                        TorLogger.Log
                                            "TorProxy: we had active circuit, no need to recreate"

                                        return lastActiveCircuit
                                    }
                                | _ ->
                                    async {
                                        TorLogger.Log
                                            "TorProxy: we didn't have an active circuit, recreating..."

                                        let! circuit =
                                            torClient.AsyncCreateCircuit
                                                3
                                                CircuitPurpose.Exit
                                                None

                                        lastActiveCircuitOpt <- Some circuit
                                        return circuit
                                    }

                            let torStream = new TorStream(circuit)

                            do!
                                torStream.ConnectToOutside
                                    parsedUrl.DnsSafeHost
                                    parsedUrl.Port
                                |> Async.Ignore

                            return torStream
                    }

                if method <> "CONNECT" then
                    let parsedUrl = Uri url

                    use! torStream = createStreamToDestination parsedUrl

                    let firstLineToRetransmit =
                        sprintf
                            "%s %s HTTP/1.1\r\n"
                            method
                            parsedUrl.PathAndQuery

                    let headersToForwardLines =
                        restOfHeaders
                        |> Seq.filter(fun header ->
                            not(header.StartsWith "Proxy-")
                        )
                        |> Seq.map(fun header -> sprintf "%s\r\n" header)

                    let headersToForward =
                        String.Join(String.Empty, headersToForwardLines)

                    do!
                        Encoding.ASCII.GetBytes firstLineToRetransmit
                        |> torStream.AsyncWrite

                    do!
                        Encoding.ASCII.GetBytes headersToForward
                        |> torStream.AsyncWrite

                    do! Encoding.ASCII.GetBytes "\r\n" |> torStream.AsyncWrite

                    return!
                        [
                            copySourceToDestination torStream stream
                            copySourceToDestination stream torStream
                        ]
                        |> Async.Parallel
                        |> Async.Ignore
                else
                    let parsedUrl = Uri <| sprintf "http://%s" url

                    use! torStream = createStreamToDestination parsedUrl

                    let connectResponse =
                        "HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n"

                    do!
                        Encoding.ASCII.GetBytes connectResponse
                        |> stream.AsyncWrite

                    return!
                        [
                            copySourceToDestination torStream stream
                            copySourceToDestination stream torStream
                        ]
                        |> Async.Parallel
                        |> Async.Ignore
            | None ->
                return failwith "TorProxy: incomplete http header detected"

        }

    let rec acceptConnections() =
        async {
            let! cancelToken = Async.CancellationToken
            cancelToken.ThrowIfCancellationRequested()

            let! client = listener.AcceptTcpClientAsync() |> Async.AwaitTask

            Async.Start(handleConnection client, cancelToken)

            return! acceptConnections()
        }

    let shutdownToken = new CancellationTokenSource()

    static member Start (localAddress: IPAddress) (port: int) =
        async {
            let! client = TorClient.AsyncBootstrapWithEmbeddedList None
            let listener = TcpListener(localAddress, port)
            let proxy = new TorProxy(listener, client)
            proxy.StartListening()
            return proxy
        }

    static member StartAsync(localAddress: IPAddress, port: int) =
        TorProxy.Start localAddress port |> Async.StartAsTask

    member private self.StartListening() =
        listener.Start()

        Async.Start(acceptConnections(), shutdownToken.Token)

    member __.GetNewIdentity() =
        async {
            let! newCircuit =
                torClient.AsyncCreateCircuit 3 CircuitPurpose.Exit None

            lastActiveCircuitOpt <- Some newCircuit
        }

    member self.GetNewIdentityAsync() =
        self.GetNewIdentity() |> Async.StartAsTask

    interface IDisposable with
        member __.Dispose() =
            shutdownToken.Cancel()
            listener.Stop()
            (torClient :> IDisposable).Dispose()
