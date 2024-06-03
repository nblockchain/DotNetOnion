namespace NOnion.TorHandshakes

open System.Security.Cryptography

open NOnion
open NOnion.Crypto.Kdf

type FastHandshake =
    private
        {
            RandomClientMaterial: array<byte>
        }

    static member Create() =
        let clientMaterial = Array.zeroCreate Constants.HashLength

        RandomNumberGenerator
            .Create()
            .GetBytes clientMaterial

        {
            RandomClientMaterial = clientMaterial
        }

    interface IHandshake with
        member self.GenerateClientMaterial() =
            self.RandomClientMaterial

        member self.GenerateKdfResult serverSideData =
            let kdfResult =
                Array.concat
                    [
                        self.RandomClientMaterial
                        serverSideData.ServerHandshake
                    ]
                |> Kdf.ComputeLegacyKdf

            if kdfResult.KeyHandshake <> serverSideData.DerivativeKey then
                raise <| HandshakeFailedException()
            else
                kdfResult
