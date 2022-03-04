namespace NOnion.Directory

open System

open NOnion
open NOnion.Utility

type DirectorySourceEntry =
    {
        NickName: Option<string>
        Identity: Option<string>
        Address: Option<string>
        IP: Option<string>
        DirectoryPort: Option<int>
        OnionRouterPort: Option<int>
        Contact: Option<string>
        VoteDigest: Option<string>
    }

    static member Empty =
        {
            DirectorySourceEntry.NickName = None
            Identity = None
            Address = None
            IP = None
            DirectoryPort = None
            OnionRouterPort = None
            Contact = None
            VoteDigest = None
        }


    static member Parse(lines: MutableQueue<string>) =
        let rec innerParse state =
            if lines.Count = 0 then
                state
            else
                let words = lines.Peek().Split ' ' |> MutableQueue<string>

                let readWord() =
                    words.Dequeue()

                let readInteger() =
                    words.Dequeue() |> int

                let readRestAsString() =
                    words.ToArray() |> String.concat " "

                match words.Dequeue() with
                | "dir-source" when state.NickName = None ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            NickName = readWord() |> Some
                            Identity = readWord() |> Some
                            Address = readWord() |> Some
                            IP = readWord() |> Some
                            DirectoryPort = readInteger() |> Some
                            OnionRouterPort = readInteger() |> Some
                        }
                | "dir-source" when state.NickName <> None -> state
                | "contact" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Contact = readRestAsString() |> Some
                        }
                | "vote-digest" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            VoteDigest = readRestAsString() |> Some
                        }
                | _ -> state

        innerParse DirectorySourceEntry.Empty

type RouterStatusEntry =
    {
        NickName: Option<string>
        Identity: Option<string>
        Digest: Option<string>
        PublicationTime: Option<DateTime>
        IP: Option<string>
        OnionRouterPort: Option<int>
        DirectoryPort: Option<int>
        Address: Option<string>
        Version: Option<string>
        Protocols: Option<string>
        Bandwidth: Option<string>
        PortPolicy: Option<string>

        Flags: seq<string>
    }

    static member Empty =
        {
            RouterStatusEntry.NickName = None
            Identity = None
            Digest = None
            PublicationTime = None
            IP = None
            DirectoryPort = None
            OnionRouterPort = None
            Address = None
            Version = None
            Protocols = None
            Bandwidth = None
            PortPolicy = None

            Flags = Seq.empty
        }

    static member Parse(lines: MutableQueue<string>) =
        let rec innerParse state =
            if lines.Count = 0 then
                state
            else
                let words = lines.Peek().Split ' ' |> MutableQueue<string>

                let readWord() =
                    words.Dequeue()

                let readInteger() =
                    words.Dequeue() |> int

                let readDateTime() =
                    String.concat " " [ words.Dequeue(); words.Dequeue() ]
                    |> DateTime.Parse

                let readRestAsString() =
                    words.ToArray() |> String.concat " "

                match words.Dequeue() with
                | "r" when state.NickName = None ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            NickName = readWord() |> Some
                            Identity = readWord() |> Some
                            Digest = readWord() |> Some
                            PublicationTime = readDateTime() |> Some
                            IP = readWord() |> Some
                            OnionRouterPort = readInteger() |> Some
                            DirectoryPort = readInteger() |> Some
                        }
                | "r" when state.NickName <> None -> state
                | "a" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Address = readRestAsString() |> Some
                        }
                | "s" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Flags =
                                readRestAsString()
                                    .Split(
                                        Array.singleton " ",
                                        StringSplitOptions.RemoveEmptyEntries
                                    )
                        }
                | "v" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Version = readRestAsString() |> Some
                        }
                | "pr" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Protocols = readRestAsString() |> Some
                        }
                | "w" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Bandwidth = readRestAsString() |> Some
                        }
                | "p" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            PortPolicy = readRestAsString() |> Some
                        }
                | _ -> state

        innerParse RouterStatusEntry.Empty

    member self.GetIdentity() =
        match self.Identity with
        | None -> failwith "BUG: identity doesn't exist in RouterStatusEntry"
        | Some identity -> identity.Trim() |> Base64Util.FixMissingPadding

type DirectorySignature =
    {
        Identity: Option<string>
        Digest: Option<string>
        Signature: Option<string>
    }

    static member Empty =
        {
            DirectorySignature.Identity = None
            Digest = None
            Signature = None
        }

    static member Parse(lines: MutableQueue<string>) =
        let rec innerParse state =
            if lines.Count = 0 then
                state
            else
                let rec readBlock(state: string) =
                    let line = lines.Dequeue()

                    if line.StartsWith "-----END" then
                        state + line
                    else
                        readBlock(state + line)

                let nextLine = lines.Peek()

                let words = nextLine.Split ' ' |> MutableQueue<string>

                let readWord() =
                    words.Dequeue()

                match words.Dequeue() with
                | "directory-signature" when state.Identity = None ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            DirectorySignature.Identity = readWord() |> Some
                            Digest = readWord() |> Some
                            Signature = readBlock String.Empty |> Some
                        }
                | "directory-signature" when state.Identity <> None -> state
                | _ -> state

        innerParse DirectorySignature.Empty

type NetworkStatusDocument =
    {
        Version: Option<int>
        VoteStatus: Option<string>
        ConsensusMethod: Option<int>
        ValidAfter: Option<DateTime>
        FreshUntil: Option<DateTime>
        ValidUntil: Option<DateTime>
        VotingDelay: Option<string>
        ClientVersions: Option<string>
        ServerVersions: Option<string>
        KnownFlags: Option<string>
        RecommendedClientProtocols: Option<string>
        RecommendedRelayProtocols: Option<string>
        RequiredClientProtocols: Option<string>
        RequiredRelayProtocols: Option<string>
        SharedRandomPreviousValue: Option<string>
        SharedRandomCurrentValue: Option<string>
        BandwithWeights: Option<string>

        Params: Map<string, string>
        Packages: List<string>
        Routers: List<RouterStatusEntry>
        Sources: List<DirectorySourceEntry>
        Signatures: List<DirectorySignature>
    }

    static member Empty =
        {
            NetworkStatusDocument.Version = None
            VoteStatus = None
            ConsensusMethod = None
            ValidAfter = None
            FreshUntil = None
            ValidUntil = None
            VotingDelay = None
            ClientVersions = None
            ServerVersions = None
            KnownFlags = None
            RecommendedClientProtocols = None
            RecommendedRelayProtocols = None
            RequiredClientProtocols = None
            RequiredRelayProtocols = None
            SharedRandomPreviousValue = None
            SharedRandomCurrentValue = None
            BandwithWeights = None

            Params = Map.empty
            Packages = List.Empty
            Routers = List.Empty
            Sources = List.Empty
            Signatures = List.Empty
        }

    static member Parse(stringToParse: string) =
        let lines = stringToParse.Split '\n' |> MutableQueue<string>

        let rec innerParse state =
            let words = lines.Peek().Split ' ' |> MutableQueue<string>

            let readDateTime() =
                String.concat " " [ words.Dequeue(); words.Dequeue() ]
                |> DateTime.Parse

            let readInt() =
                words.Dequeue() |> int

            let readRestAsString() =
                words.ToArray() |> String.concat " "

            let newState: NetworkStatusDocument =
                match words.Dequeue() with
                | "network-status-version" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        Version = readInt() |> Some
                    }
                | "vote-status" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        VoteStatus = readRestAsString() |> Some
                    }
                | "consensus-method" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        ConsensusMethod = readInt() |> Some
                    }
                | "valid-after" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        ValidAfter = readDateTime() |> Some
                    }
                | "fresh-until" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        FreshUntil = readDateTime() |> Some
                    }
                | "valid-until" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        ValidUntil = readDateTime() |> Some
                    }
                | "voting-delay" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        VotingDelay = readRestAsString() |> Some
                    }
                | "client-versions" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        ClientVersions = readRestAsString() |> Some
                    }
                | "server-versions" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        ServerVersions = readRestAsString() |> Some
                    }
                | "package" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        Packages =
                            state.Packages @ List.singleton(readRestAsString())
                    }
                | "known-flags" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        KnownFlags = readRestAsString() |> Some
                    }
                | "recommended-client-protocols" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        RecommendedClientProtocols = readRestAsString() |> Some
                    }
                | "recommended-relay-protocols" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        RecommendedRelayProtocols = readRestAsString() |> Some
                    }
                | "required-client-protocols" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        RequiredClientProtocols = readRestAsString() |> Some
                    }
                | "required-relay-protocols" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        RequiredRelayProtocols = readRestAsString() |> Some
                    }
                | "params" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        Params =
                            readRestAsString().Split(' ')
                            |> Seq.map(fun param ->
                                let keyValue = param.Split('=')
                                keyValue.[0], keyValue.[1]
                            )
                            |> Map.ofSeq
                    }
                | "shared-rand-previous-value" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        SharedRandomPreviousValue = readRestAsString() |> Some
                    }
                | "shared-rand-current-value" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        SharedRandomCurrentValue = readRestAsString() |> Some
                    }
                | "bandwidth-weights" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        BandwithWeights = readRestAsString() |> Some
                    }
                | "dir-source" ->
                    { state with
                        Sources =
                            state.Sources
                            @ List.singleton(DirectorySourceEntry.Parse lines)
                    }
                | "r" ->
                    { state with
                        Routers =
                            state.Routers
                            @ List.singleton(RouterStatusEntry.Parse lines)
                    }
                | "directory-signature" ->
                    { state with
                        Signatures =
                            state.Signatures
                            @ List.singleton(DirectorySignature.Parse lines)
                    }
                | _ ->
                    lines.Dequeue() |> ignore<string>
                    state

            if lines.Count > 0 then
                innerParse newState
            else
                newState

        innerParse NetworkStatusDocument.Empty

    member self.GetHiddenServicesDirectoryInterval() =
        match self.Params.TryFind "hsdir-interval" with
        | None -> Constants.DefaultHSDirInterval
        | Some hsDirinterval -> hsDirinterval |> Convert.ToInt32

    member self.GetValidAfter() =
        match self.ValidAfter with
        | None ->
            failwith "BUG: valid-after field does not exist in the consensus"
        | Some validAfter -> validAfter

    member self.GetValidUntil() =
        match self.ValidUntil with
        | None ->
            failwith "BUG: valid-until field does not exist in the consensus"
        | Some validUntil -> validUntil


    member self.GetTimePeriod() =
        let validAfterInMinutes =
            let validAfterSinceEpoch =
                self.GetValidAfter() |> DateTimeUtils.GetTimeSpanSinceEpoch

            validAfterSinceEpoch
                .Subtract(
                    Constants.RotationTimeOffset
                )
                .TotalMinutes

        let hsDirInterval = self.GetHiddenServicesDirectoryInterval()

        validAfterInMinutes / (hsDirInterval |> float) |> Math.Floor |> uint64,
        hsDirInterval |> uint64
