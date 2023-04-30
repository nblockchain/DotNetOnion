namespace NOnion.Directory

open System
open System.Text

open Org.BouncyCastle.Crypto.Signers
open Org.BouncyCastle.Crypto.Parameters

open NOnion
open NOnion.Utility

type HiddenServiceFirstLayerDescriptorDocument =
    {
        Version: Option<int>
        Lifetime: Option<int>
        SigningKeyCert: Option<Certificate>
        RevisionCounter: Option<int64>
        EncryptedPayload: Option<array<byte>>
        Signature: Option<array<byte>>
    }

    static member CreateNew
        version
        lifetime
        signingKeyCert
        revision
        payload
        signingPrivateKey
        =
        let unsignedOuterWrapper =
            {
                HiddenServiceFirstLayerDescriptorDocument.EncryptedPayload =
                    Some payload
                Version = version |> Some
                Lifetime = Some lifetime
                RevisionCounter = revision
                Signature = None
                SigningKeyCert = Some signingKeyCert
            }

        let unsignedOuterWrapperInBytes =
            Constants.HiddenServices.Descriptor.SigningPrefix
            + unsignedOuterWrapper.ToString()
            |> System.Text.Encoding.ASCII.GetBytes

        let signer = Ed25519Signer()
        signer.Init(true, signingPrivateKey)

        signer.BlockUpdate(
            unsignedOuterWrapperInBytes,
            0,
            unsignedOuterWrapperInBytes.Length
        )

        let signature = signer.GenerateSignature()

        { unsignedOuterWrapper with
            Signature = Some signature
        }

    static member Empty =
        {
            HiddenServiceFirstLayerDescriptorDocument.Version = None
            Lifetime = None
            SigningKeyCert = None
            RevisionCounter = None
            EncryptedPayload = None
            Signature = None
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

            let readInteger() =
                words.Dequeue() |> int

            let readLong() =
                words.Dequeue() |> Convert.ToInt64

            let readRestAsString() =
                words.ToArray() |> String.concat " "

            let newState =
                match words.Dequeue() with
                | "signature" ->
                    lines.Dequeue() |> ignore<string>
                    let signature = readRestAsString() |> Base64Util.FromString

                    match state.SigningKeyCert with
                    | Some keyCert ->
                        let signatureIndex = stringToParse.IndexOf("signature")

                        let documentExcludingSignature =
                            stringToParse.Substring(0, signatureIndex)

                        let signer = Ed25519Signer()

                        signer.Init(
                            false,
                            Ed25519PublicKeyParameters(keyCert.CertifiedKey, 0)
                        )

                        let currentStateInBytes =
                            Constants.HiddenServices.Descriptor.SigningPrefix
                            + documentExcludingSignature
                            |> Encoding.ASCII.GetBytes

                        signer.BlockUpdate(
                            currentStateInBytes,
                            0,
                            currentStateInBytes.Length
                        )

                        if not(signer.VerifySignature(signature)) then
                            failwith
                                "Can't parse hs document(outer-wrapper), invalid signature"
                    | None ->
                        failwith
                            "Can't parse hs document(outer-wrapper), signature should be the last item in the doc"

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.Signature =
                            Some signature
                    }
                | "hs-descriptor" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.Version =
                            readInteger() |> Some
                    }
                | "descriptor-lifetime" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.Lifetime =
                            readInteger() |> Some
                    }
                | "descriptor-signing-key-cert" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.SigningKeyCert =
                            readBlock String.Empty
                            |> PemUtility.PemToByteArray
                            |> Certificate.FromBytes
                            |> Some
                    }
                | "revision-counter" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.RevisionCounter =
                            readLong() |> Some
                    }
                | "superencrypted" ->
                    lines.Dequeue() |> ignore<string>

                    { state with
                        HiddenServiceFirstLayerDescriptorDocument.EncryptedPayload =
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

        innerParse HiddenServiceFirstLayerDescriptorDocument.Empty

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

        match self.Version with
        | Some version ->
            appendLine(sprintf "hs-descriptor %i" version)
            |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (outer wrapper) is incomplete, missing version"

        match self.Lifetime with
        | Some lifeTime ->
            appendLine(sprintf "descriptor-lifetime %i" lifeTime)
            |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (outer wrapper) is incomplete, missing lifetime"

        match self.SigningKeyCert with
        | Some keyCert ->
            appendLine "descriptor-signing-key-cert" |> ignore<StringBuilder>
            appendLine "-----BEGIN ED25519 CERT-----" |> ignore<StringBuilder>

            keyCert.ToBytes false
            |> writeByteArray
            |> appendLine
            |> ignore<StringBuilder>

            appendLine "-----END ED25519 CERT-----" |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (outer wrapper) is incomplete, missing signing key cert"

        match self.RevisionCounter with
        | Some counter ->
            appendLine(sprintf "revision-counter %i" counter)
            |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (outer wrapper) is incomplete, missing revision-counter"

        match self.EncryptedPayload with
        | Some encrypted ->
            appendLine "superencrypted" |> ignore<StringBuilder>
            appendLine "-----BEGIN MESSAGE-----" |> ignore<StringBuilder>
            writeByteArray encrypted |> appendLine |> ignore<StringBuilder>
            appendLine "-----END MESSAGE-----" |> ignore<StringBuilder>
        | None ->
            failwith
                "HS document (outer wrapper) is incomplete, missing payload"

        match self.Signature with
        | Some signature when signature.Length > 0 ->
            appendLine(
                sprintf "signature %s" (Base64Util.EncodeNoPadding signature)
            )
            |> ignore<StringBuilder>
        | _ -> ()

        strBuilder.ToString()
