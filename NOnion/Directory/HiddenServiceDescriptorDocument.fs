namespace NOnion.Directory

open System
open System.Text

open NOnion
open NOnion.Utility

type IntroductionPointEntry =
    {
        OnionKey: Option<NTorOnionKey>
        AuthKey: Option<Certificate>
        EncKey: Option<array<byte>>
        EncKeyCert: Option<Certificate>
        LinkSpecifiers: Option<array<byte>>
    }

    static member Empty =
        {
            IntroductionPointEntry.OnionKey = None
            AuthKey = None
            EncKey = None
            EncKeyCert = None
            LinkSpecifiers = None
        }

    static member Parse(lines: MutableQueue<string>) =
        let rec innerParse state =
            if lines.Count = 0 then
                state
            else
                let words = lines.Peek().Split ' ' |> MutableQueue<string>

                let rec readBlock(state: string) =
                    let line = sprintf "%s\n" (lines.Dequeue())

                    if line.StartsWith "-----END" then
                        state + line
                    else
                        readBlock(state + line)

                let readWord() =
                    words.Dequeue()

                match words.Dequeue() with
                | "introduction-point" when state.LinkSpecifiers = None ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            LinkSpecifiers =
                                readWord() |> Convert.FromBase64String |> Some
                        }
                | "introduction-point" when state.LinkSpecifiers <> None ->
                    state
                | "onion-key" ->
                    lines.Dequeue() |> ignore<string>
                    readWord() |> ignore<string>

                    innerParse
                        { state with
                            OnionKey =
                                readWord()
                                |> Convert.FromBase64String
                                |> NTorOnionKey
                                |> Some
                        }
                | "enc-key" ->
                    lines.Dequeue() |> ignore<string>
                    readWord() |> ignore<string>

                    innerParse
                        { state with
                            EncKey =
                                readWord() |> Convert.FromBase64String |> Some
                        }
                | "auth-key" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            AuthKey =
                                readBlock String.Empty
                                |> PemUtility.PemToByteArray
                                |> Certificate.FromBytes
                                |> Some
                        }
                | "enc-key-cert" ->
                    lines.Dequeue() |> ignore<string>

                    innerParse
                        { state with
                            EncKeyCert =
                                readBlock String.Empty
                                |> PemUtility.PemToByteArray
                                |> Certificate.FromBytes
                                |> Some
                        }

                | _ -> state

        innerParse IntroductionPointEntry.Empty

    override self.ToString() =
        let strBuilder = StringBuilder()

        let writeByteArray data =
            let dataInString = data |> Convert.ToBase64String

            let chunkedData =
                dataInString.ToCharArray()
                |> Array.chunkBySize Constants.DirectoryBlockLineLength
                |> Array.map String

            String.Join("\n", chunkedData)

        let appendLine str =
            strBuilder.Append(sprintf "%s\n" str)

        match self.LinkSpecifiers with
        | Some linkSpecifier ->
            appendLine(
                sprintf
                    "introduction-point %s"
                    (Convert.ToBase64String linkSpecifier)
            )
            |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (most inner wrapper) is incomplete, missing linkspecifier"

        match self.OnionKey with
        | Some nTorOnionKey ->
            appendLine(
                sprintf
                    "onion-key ntor %s"
                    (Convert.ToBase64String <| nTorOnionKey.ToByteArray())
            )
            |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (most inner wrapper) is incomplete, missing OnionKey"

        match self.AuthKey with
        | Some authKey ->
            appendLine "auth-key" |> ignore<StringBuilder>
            appendLine "-----BEGIN ED25519 CERT-----" |> ignore<StringBuilder>

            authKey.ToBytes false
            |> writeByteArray
            |> appendLine
            |> ignore<StringBuilder>

            appendLine "-----END ED25519 CERT-----" |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (outer wrapper) is incomplete, missing AuthKey"

        match self.EncKey with
        | Some encKey ->
            appendLine(
                sprintf "enc-key ntor %s" (Convert.ToBase64String encKey)
            )
            |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (most inner wrapper) is incomplete, missing EncKey"

        match self.EncKeyCert with
        | Some encKeyCert ->
            appendLine "enc-key-cert" |> ignore<StringBuilder>
            appendLine "-----BEGIN ED25519 CERT-----" |> ignore<StringBuilder>

            encKeyCert.ToBytes false
            |> writeByteArray
            |> appendLine
            |> ignore<StringBuilder>

            appendLine "-----END ED25519 CERT-----" |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (outer wrapper) is incomplete, missing EncKeyCert"

        strBuilder.ToString()


type HiddenServiceDescriptorDocument =
    {
        Create2Formats: Option<string>
        IsSingleOnionService: bool

        IntroductionPoints: List<IntroductionPointEntry>
    }

    static member Empty =
        {
            HiddenServiceDescriptorDocument.Create2Formats = None
            IsSingleOnionService = false

            IntroductionPoints = List.empty
        }

    static member Default =
        let ntorCreateFormat = "2"

        { HiddenServiceDescriptorDocument.Empty with
            Create2Formats = Some ntorCreateFormat
        }

    static member Parse(stringToParse: string) =
        let lines = stringToParse.Split '\n' |> MutableQueue<string>

        let rec readBlock(state: string) =
            let line = sprintf "%s\n" (lines.Dequeue())

            if line.StartsWith "-----END" then
                state + line
            else
                readBlock(state + line)

        let rec innerParse state =

            let words = lines.Peek().Split ' ' |> MutableQueue<string>

            let readRestAsString() =
                words.ToArray() |> String.concat " "

            let newState =
                match words.Dequeue() with
                | "create2-formats" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceDescriptorDocument.Create2Formats =
                            readRestAsString() |> Some
                    }
                | "intro-auth-required" ->
                    failwith "NOnion doesn't support client-authorization"
                | "single-onion-service" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceDescriptorDocument.IsSingleOnionService =
                            true
                    }
                | "introduction-point" ->
                    { state with
                        IntroductionPoints =
                            state.IntroductionPoints
                            @ List.singleton(IntroductionPointEntry.Parse lines)
                    }
                | _ ->
                    lines.Dequeue() |> ignore<string>
                    state

            if lines.Count > 0 then
                innerParse newState
            else
                newState

        innerParse HiddenServiceDescriptorDocument.Empty

    override self.ToString() =
        let strBuilder = StringBuilder()

        let appendLine str =
            strBuilder.Append(sprintf "%s\n" str)

        match self.Create2Formats with
        | Some formats ->
            appendLine(sprintf "create2-formats %s" formats)
            |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (most inner wrapper) is incomplete, missing Create2Formats"

        if self.IsSingleOnionService then
            appendLine "single-onion-service" |> ignore<StringBuilder>

        for introductionPoint in self.IntroductionPoints do
            strBuilder.Append(introductionPoint.ToString())
            |> ignore<StringBuilder>

        strBuilder.ToString()
