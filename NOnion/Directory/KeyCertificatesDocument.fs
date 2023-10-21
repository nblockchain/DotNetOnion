namespace NOnion.Directory

open System
open System.Text

open Org.BouncyCastle.Asn1

open NOnion.Crypto.DirectoryCipher
open NOnion.Utility.AsyncUtil
open NOnion.Utility.PemUtility

type KeyCertificateEntry =
    {
        Version: Option<int>
        Address: Option<string>
        Fingerprint: Option<string>
        IdentityKey: Option<string>
        Published: Option<string>
        Expires: Option<string>
        SigningKey: Option<string>
        CrossCert: Option<string>
        Certification: Option<string>
    }

    static member Empty =
        {
            Version = None
            Address = None
            Fingerprint = None
            IdentityKey = None
            Published = None
            Expires = None
            SigningKey = None
            CrossCert = None
            Certification = None
        }

    static member ParseMany(stringToParse: string) =
        let lines = stringToParse.Split '\n' |> MutableQueue<string>

        let history = StringBuilder()

        let clearHistory = history.Clear

        let dequeueLineAndAddToHistory() =
            let line = lines.Dequeue()
            history.Append(sprintf "%s\n" line) |> ignore<StringBuilder>
            line

        let rec innerParse
            (state: KeyCertificateEntry)
            (previousEntries: List<KeyCertificateEntry>)
            =
            let rec readBlock(state: string) =
                let line = sprintf "%s\n" (dequeueLineAndAddToHistory())

                if line.StartsWith "-----END" then
                    state + line
                else
                    readBlock(state + line)

            let validate (state: KeyCertificateEntry) (history: string) =
                let identityKey =
                    UnwrapOption
                        state.IdentityKey
                        "KeyCertificate validation failed: Identity key not found"
                    |> GetRsaKeyParametersFromPem

                let signingKey =
                    UnwrapOption
                        state.SigningKey
                        "KeyCertificate validation failed: Signing key not found"
                    |> GetRsaKeyParametersFromPem

                let decryptedCrossCertHash =
                    UnwrapOption
                        state.CrossCert
                        "KeyCertificate validation failed: Cross cert not found"
                    |> PemToByteArray
                    |> DecryptSignature signingKey

                //FIXME: maybe this is useful for other placees later
                let computedCrossCertHash =
                    let modulus = DerInteger identityKey.Modulus
                    let exponent = DerInteger identityKey.Exponent

                    let derSeq =
                        DerSequence
                            [|
                                modulus :> Asn1Encodable
                                exponent :> Asn1Encodable
                            |]

                    derSeq.GetEncoded() |> SHA1

                if decryptedCrossCertHash <> computedCrossCertHash then
                    failwith
                        "KeyCertificate validation failed: Crosscert validation failed"

                let decryptedDocumentDigest =
                    UnwrapOption
                        state.Certification
                        "KeyCertificate validation failed: Certification not found"
                    |> PemToByteArray
                    |> DecryptSignature identityKey

                let computedDocumentDigest =
                    history |> Encoding.ASCII.GetBytes |> SHA1

                if decryptedDocumentDigest <> computedDocumentDigest then
                    failwith
                        "KeyCertificate validation failed: Certification validation failed"

                // Clear history before we move on to next item
                clearHistory() |> ignore<StringBuilder>

                innerParse KeyCertificateEntry.Empty (state :: previousEntries)

            if Seq.isEmpty lines then
                previousEntries
            else
                let nextLine = lines.Peek()

                let words = nextLine.Split ' ' |> MutableQueue<string>

                let readRestAsString() =
                    words.ToArray() |> String.concat " "

                let readInt() =
                    words.Dequeue() |> int

                match words.Dequeue() with
                | "dir-key-certificate-version" when state.Version.IsNone ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Version = readInt() |> Some
                        }
                        previousEntries
                | "dir-key-certificate-version" when not state.Version.IsNone ->
                    failwith
                        "Should not happen: dir-key-certificate-version seen when already initialized"
                | "dir-address" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Address = readRestAsString() |> Some
                        }
                        previousEntries
                | "fingerprint" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Fingerprint = readRestAsString() |> Some
                        }
                        previousEntries
                | "dir-identity-key" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            IdentityKey = readBlock String.Empty |> Some
                        }
                        previousEntries
                | "dir-key-published" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Published = readRestAsString() |> Some
                        }
                        previousEntries
                | "dir-key-expires" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            Expires = readRestAsString() |> Some
                        }
                        previousEntries
                | "dir-signing-key" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            SigningKey = readBlock String.Empty |> Some
                        }
                        previousEntries
                | "dir-key-crosscert" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    innerParse
                        { state with
                            CrossCert = readBlock String.Empty |> Some
                        }
                        previousEntries
                | "dir-key-certification" ->
                    dequeueLineAndAddToHistory() |> ignore<string>

                    let historyBeforeCertification = history.ToString()

                    validate
                        { state with
                            Certification = readBlock String.Empty |> Some
                        }
                        historyBeforeCertification
                | _ ->
                    //Ignore possible unknown items (future-proofness)
                    dequeueLineAndAddToHistory() |> ignore<string>
                    innerParse state previousEntries

        innerParse KeyCertificateEntry.Empty List.Empty
