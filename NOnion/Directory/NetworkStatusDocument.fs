namespace NOnion.Directory

open System
open System.Text

open Newtonsoft.Json

open NOnion
open NOnion.Crypto.DirectoryCipher
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
        /// This is the digest of router's microdescriptor and can't be used
        /// as digest of router's server descriptor
        MicroDescriptorDigest: Option<string>
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
            MicroDescriptorDigest = None
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
                            PublicationTime = readDateTime() |> Some
                            IP = readWord() |> Some
                            OnionRouterPort = readInteger() |> Some
                            DirectoryPort = readInteger() |> Some
                        }
                | "r" when state.NickName <> None -> state
                | "m" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            MicroDescriptorDigest = readWord() |> Some
                        }
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
        | Some identity -> identity

type DirectorySignature =
    {
        Algorithm: Option<string>
        Identity: Option<string>
        SigningKeyDigest: Option<string>
        Signature: Option<string>
    }

    static member Empty =
        {
            DirectorySignature.Algorithm = None
            Identity = None
            SigningKeyDigest = None
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
                        readBlock(state + line + "\n")

                let nextLine = lines.Peek()

                let words = nextLine.Split ' ' |> MutableQueue<string>

                let readWord() =
                    words.Dequeue()

                match words.Dequeue() with
                | "directory-signature" when state.Identity = None ->
                    lines.Dequeue() |> ignore<string>

                    let algs = [ "sha1"; "sha256" ]
                    let maybeAlg = readWord()

                    if Seq.contains maybeAlg algs then
                        innerParse
                            { state with
                                DirectorySignature.Algorithm = maybeAlg |> Some
                                Identity = readWord() |> Some
                                SigningKeyDigest = readWord() |> Some
                                Signature = readBlock String.Empty |> Some
                            }
                    else
                        innerParse
                            { state with
                                DirectorySignature.Algorithm = "sha1" |> Some
                                Identity = readWord() |> Some
                                SigningKeyDigest = readWord() |> Some
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

        [<JsonIgnore>]
        SHA1Digest: Option<array<byte>>
        [<JsonIgnore>]
        SHA256Digest: Option<array<byte>>

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

            SHA1Digest = None
            SHA256Digest = None

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
                        SharedRandomPreviousValue =
                            readRestAsString().Split(' ').[1] |> Some
                    }
                | "shared-rand-current-value" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        SharedRandomCurrentValue =
                            readRestAsString().Split(' ').[1] |> Some
                    }
                | "bandwidth-weights" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        BandwithWeights = readRestAsString() |> Some
                    }
                | "dir-source" ->
                    { state with
                        Sources =
                            DirectorySourceEntry.Parse lines :: state.Sources
                    }
                | "r" ->
                    { state with
                        Routers = RouterStatusEntry.Parse lines :: state.Routers
                    }
                | "directory-signature" ->
                    let documentForDigest =
                        stringToParse.Split(
                            Array.singleton "directory-signature",
                            StringSplitOptions.RemoveEmptyEntries
                        ).[0]
                        + "directory-signature "

                    { state with
                        SHA1Digest =
                            Encoding.ASCII.GetBytes documentForDigest
                            |> SHA1
                            |> Some
                        SHA256Digest =
                            Encoding.ASCII.GetBytes documentForDigest
                            |> SHA256
                            |> Some
                        Signatures =
                            DirectorySignature.Parse lines :: state.Signatures
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

    member self.GetFreshUntil() =
        match self.FreshUntil with
        | None ->
            failwith "BUG: fresh-until field does not exist in the consensus"
        | Some freshUntil -> freshUntil

    member self.GetVotingInterval() =
        self.GetFreshUntil() - self.GetValidAfter()

    member self.IsLive() =
        let now = DateTime.UtcNow

        self.GetValidAfter() < now && self.GetValidUntil() > now

    member self.GetTimePeriod() =
        let hsDirInterval = self.GetHiddenServicesDirectoryInterval()

        HiddenServicesUtility.GetTimePeriod (self.GetValidAfter()) hsDirInterval
        |> uint64,
        hsDirInterval |> uint64

    member self.GetCurrentSRVForClient() =
        let isInBetweenTpAndSRV =
            HiddenServicesUtility.InPeriodBetweenTPAndSRV
                (self.GetValidAfter())
                (self.GetVotingInterval())
                (self.GetHiddenServicesDirectoryInterval())

        if isInBetweenTpAndSRV then
            self.SharedRandomCurrentValue.Value
        else
            self.SharedRandomPreviousValue.Value

    //HACK: document parser needs to parse ranges but here we use string search instead
    member self.GetHiddenServiceDirectories() =
        self.Routers
        |> List.filter(fun router ->
            router.Flags |> Seq.contains "HSDir"
            && router.Flags |> Seq.contains "NoEdConsensus" |> not
            && (router.Protocols.Value.Contains("HSDir=1-2")
                || router.Protocols.Value.Contains("HSDir=2"))
        )
