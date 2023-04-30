namespace NOnion.Directory

open System
open System.Text

open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Security

open NOnion
open NOnion.Utility

type HiddenServiceSecondLayerDescriptorDocument =
    {
        EncryptedPayload: Option<array<byte>>
    }

    static member Empty =
        {
            HiddenServiceSecondLayerDescriptorDocument.EncryptedPayload = None
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

            let newState =
                match words.Dequeue() with
                | "encrypted" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceSecondLayerDescriptorDocument.EncryptedPayload =
                            readBlock String.Empty
                            |> PemUtility.PemToByteArray
                            |> Some
                    }
                | _ ->
                    lines.Dequeue() |> ignore<string>
                    state

            if lines.Count > 0 then
                innerParse newState
            else
                newState

        innerParse HiddenServiceSecondLayerDescriptorDocument.Empty

    override self.ToString() =
        let writeByteArray data =
            let dataInString = data |> Convert.ToBase64String

            let chunkedData =
                dataInString.ToCharArray()
                |> Array.chunkBySize Constants.DirectoryBlockLineLength
                |> Array.map String

            String.Join("\n", chunkedData)

        let strBuilder = StringBuilder()

        let appendLine str =
            strBuilder.Append(sprintf "%s\n" str)

        let ephemeralKey =
            let kpGen = X25519KeyPairGenerator()
            let random = SecureRandom()
            kpGen.Init(X25519KeyGenerationParameters random)
            let keyPair = kpGen.GenerateKeyPair()

            (keyPair.Public :?> X25519PublicKeyParameters)
                .GetEncoded()
            |> Convert.ToBase64String

        appendLine "desc-auth-type x25519" |> ignore<StringBuilder>

        appendLine(sprintf "desc-auth-ephemeral-key %s" ephemeralKey)
        |> ignore<StringBuilder>

        let authClientLine =
            let random = SecureRandom()

            let clientId = Array.zeroCreate 8
            let iv = Array.zeroCreate 16
            let cookie = Array.zeroCreate 16

            random.NextBytes clientId
            random.NextBytes iv
            random.NextBytes cookie

            sprintf
                "%s %s %s"
                (Base64Util.EncodeNoPadding clientId)
                (Base64Util.EncodeNoPadding iv)
                (Base64Util.EncodeNoPadding cookie)

        appendLine(sprintf "auth-client %s" authClientLine)
        |> ignore<StringBuilder>

        match self.EncryptedPayload with
        | Some encrypted ->
            appendLine "encrypted" |> ignore<StringBuilder>
            appendLine "-----BEGIN MESSAGE-----" |> ignore<StringBuilder>
            writeByteArray encrypted |> appendLine |> ignore<StringBuilder>
            appendLine "-----END MESSAGE-----" |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (outer wrapper) is incomplete, missing payload"

        strBuilder.ToString()
