namespace NOnion

open System

type NOnionException =
    inherit Exception

    internal new(msg: string) = { inherit Exception(msg) }

    internal new(msg: string, innerException: Exception) =
        { inherit Exception(msg, innerException) }

type GuardConnectionFailedException =
    inherit NOnionException

    internal new(innerException: Exception) =
        { inherit NOnionException("Connecting to guard node failed",
                                  innerException) }

    internal new(message: string) =
        { inherit NOnionException("Connecting to guard node failed: " + message) }

type CircuitTruncatedException internal (reason: DestroyReason) =
    inherit NOnionException(sprintf "Circuit got truncated, reason %A" reason)

type CircuitDestroyedException internal (reason: DestroyReason) =
    inherit NOnionException(sprintf "Circuit got destroyed, reason %A" reason)

type CircuitDecryptionFailedException internal () =
    inherit NOnionException(sprintf "Circuit Decryption Failed")

type HandshakeFailedException internal () =
    inherit NOnionException(sprintf "Key handshake failed!")

type TimeoutErrorException internal () =
    inherit NOnionException("Time limit exceeded for operation")

type UnsuccessfulHttpResponseException internal (statusCode: string) =
    inherit NOnionException(sprintf
                                "Non-200 status code received, code: %s"
                                statusCode)

type UnsuccessfulIntroductionException internal (status: RelayIntroduceStatus) =
    inherit NOnionException(sprintf "Unsuccessful introduction: %A" status)

type IntroductoinPointsKilledException() =
    inherit NOnionException("Introduction points got disconnected, please try again!")

type DescriptorDownloadFailedException() =
    inherit NOnionException("Can't download descriptor, all requests failed.")

type NOnionSocketException
    internal
    (
        innerException: Net.Sockets.SocketException
    ) =
    inherit NOnionException
        (
            "Got socket exception during data transfer",
            innerException
        )
