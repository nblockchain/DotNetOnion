namespace NOnion.Directory

open System

type internal MutableQueue<'T> = System.Collections.Generic.Queue<'T>

type ServerDescriptorEntry =
    {
        Nickname: Option<string>
        Address: Option<string>
        OnionRouterPort: Option<int>
        SocksPort: Option<int>
        DirectoryPort: Option<int>
        IdentityEd25519: Option<string>
        MasterKeyEd25519: Option<string>
        Bandwidth: Option<string>
        Platform: Option<string>
        Published: Option<DateTime>
        Fingerprint: Option<string>
        Hibernating: bool
        Uptime: Option<int>
        OnionKey: Option<string>
        OnionKeyCrossCert: Option<string>
        NTorOnionKey: Option<string>
        NTorOnionKeyCrossCert: Option<int * string>
        SigningKey: Option<string>
        Accept: Option<string>
        Reject: Option<string>
        IpV6Policy: Option<string>
        OverloadGeneral: Option<string>
        RouterSigEd25519: Option<string>
        RouterSignature: Option<string>
        Contact: Option<string>
        BridgeDistributionRequest: Option<string>
        Family: Option<string>
        ReadHistory: Option<string>
        WriteHistory: Option<string>
        EventDNS: Option<bool>
        CachesExtraInfo: Option<string>
        ExtraInfoDigest: Option<string>
        HiddenServiceDir: bool
        Protocols: Option<string>
        AllowSingleHopExits: bool
        OnionRouterAddress: Option<string>
        TunnelledDirServer: bool
        Proto: Option<string>
    }

    static member Empty =
        {
            Nickname = None
            Address = None
            OnionRouterPort = None
            SocksPort = None
            DirectoryPort = None
            IdentityEd25519 = None
            MasterKeyEd25519 = None
            Bandwidth = None
            Platform = None
            Published = None
            Fingerprint = None
            Hibernating = false
            Uptime = None
            OnionKey = None
            OnionKeyCrossCert = None
            NTorOnionKey = None
            NTorOnionKeyCrossCert = None
            SigningKey = None
            Accept = None
            Reject = None
            IpV6Policy = None
            OverloadGeneral = None
            RouterSigEd25519 = None
            RouterSignature = None
            Contact = None
            BridgeDistributionRequest = None
            Family = None
            ReadHistory = None
            WriteHistory = None
            EventDNS = None
            CachesExtraInfo = None
            ExtraInfoDigest = None
            HiddenServiceDir = false
            Protocols = None
            AllowSingleHopExits = false
            OnionRouterAddress = None
            TunnelledDirServer = false
            Proto = None
        }

    static member Parse(lines: MutableQueue<string>) =
        let rec innerParse state =
            let rec readBlock(state: string) =
                let line = lines.Dequeue()

                if line.StartsWith "-----END" then
                    state + line
                else
                    readBlock(state + line)

            if lines.Count = 0 then
                state
            else
                let nextLine = lines.Peek()

                let words = nextLine.Split ' ' |> MutableQueue<string>

                let readDateTime() =
                    String.concat " " [ words.Dequeue(); words.Dequeue() ]
                    |> DateTime.Parse

                let readInt() =
                    words.Dequeue() |> int

                let readRestAsString() =
                    words.ToArray() |> String.concat " "

                let readWord() =
                    words.Dequeue()

                match words.Dequeue() with
                | "router" when state.Nickname = None ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Nickname = readWord() |> Some
                            Address = readWord() |> Some
                            OnionRouterPort = readInt() |> Some
                            SocksPort = readInt() |> Some
                            DirectoryPort = readInt() |> Some
                        }
                | "identity-ed25519" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            IdentityEd25519 = readBlock String.Empty |> Some
                        }
                | "master-key-ed25519" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            MasterKeyEd25519 = readRestAsString() |> Some
                        }
                | "bandwidth" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Bandwidth = readRestAsString() |> Some
                        }
                | "platform" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Platform = readRestAsString() |> Some
                        }
                | "published" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Published = readDateTime() |> Some
                        }
                | "fingerprint" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Fingerprint =
                                (readRestAsString()).Replace(" ", String.Empty)
                                |> Some
                        }
                | "hibernating" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Hibernating = readInt() |> Convert.ToBoolean
                        }
                | "uptime" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Uptime = readInt() |> Some
                        }
                | "onion-key" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            OnionKey = readBlock String.Empty |> Some
                        }
                | "onion-key-crosscert" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            OnionKeyCrossCert = readBlock String.Empty |> Some
                        }
                | "ntor-onion-key" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            NTorOnionKey = readRestAsString() |> Some
                        }
                | "ntor-onion-key-crosscert" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            NTorOnionKeyCrossCert =
                                (readInt(), readBlock String.Empty) |> Some
                        }
                | "signing-key" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            SigningKey = readBlock String.Empty |> Some
                        }
                | "accept" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Accept = readRestAsString() |> Some
                        }
                | "reject" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Reject = readRestAsString() |> Some
                        }
                | "ipv6-policy" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Reject = readRestAsString() |> Some
                        }
                | "ipv6-policy" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            IpV6Policy = readRestAsString() |> Some
                        }
                | "overload-general" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            OverloadGeneral = readRestAsString() |> Some
                        }
                | "router-sig-ed25519" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            RouterSigEd25519 = readRestAsString() |> Some
                        }
                | "router-signature" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            RouterSignature = readBlock String.Empty |> Some
                        }
                | "contact" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Contact = readRestAsString() |> Some
                        }
                | "bridge-distribution-request" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            BridgeDistributionRequest =
                                readRestAsString() |> Some
                        }
                | "family" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Family = readRestAsString() |> Some
                        }
                | "read-history" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            ReadHistory = readRestAsString() |> Some
                        }
                | "write-history" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            WriteHistory = readRestAsString() |> Some
                        }
                | "eventdns" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            EventDNS = readInt() |> Convert.ToBoolean |> Some
                        }
                | "extra-info-digest" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            ExtraInfoDigest = readRestAsString() |> Some
                        }
                | "hidden-service-dir" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            HiddenServiceDir = true
                        }
                | "protocols" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Protocols = readRestAsString() |> Some
                        }
                | "allow-single-hop-exits" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            AllowSingleHopExits = true
                        }
                | "or-address" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            OnionRouterAddress = readRestAsString() |> Some
                        }
                | "tunnelled-dir-server" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            TunnelledDirServer = true
                        }
                | "proto" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            Proto = readRestAsString() |> Some
                        }
                | "router" when state.Nickname <> None -> state
                | _ -> state

        innerParse ServerDescriptorEntry.Empty


type ServerDescriptorsDocument =
    {
        Routers: List<ServerDescriptorEntry>
    }

    static member Empty =
        {
            ServerDescriptorsDocument.Routers = List.empty
        }

    static member Parse(stringToParse: string) =
        let lines = stringToParse.Split '\n' |> MutableQueue<string>

        let rec innerParse state =
            let words = lines.Peek().Split ' ' |> MutableQueue<string>

            let newState =
                match words.Dequeue() with
                | "router" ->
                    { state with
                        Routers =
                            state.Routers
                            @ List.singleton(ServerDescriptorEntry.Parse lines)
                    }
                | _ ->
                    lines.Dequeue() |> ignore<string>
                    state

            if lines.Count > 0 then
                innerParse newState
            else
                newState

        innerParse ServerDescriptorsDocument.Empty
