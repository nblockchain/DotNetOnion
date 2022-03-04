namespace NOnion.Crypto

open System.Security.Cryptography
open System

type TorStreamCipher(keyBytes: array<byte>, ivOpt: Option<array<byte>>) =

    [<Literal>]
    let BlockSize = 16

    // This bytearray isn't mutable but the content of it is constantly changing so a lock is needed to prevent issues.
    let counter: array<byte> =
        match ivOpt with
        | Some iv when iv.Length = BlockSize -> Array.copy iv
        | _ -> Array.zeroCreate<byte> BlockSize

    let counterOut: array<byte> = Array.zeroCreate BlockSize
    let mutable keyStreamPointerOpt: Option<int> = None

    let encryptLock: obj = obj()

    member self.Encrypt(data: array<byte>) : array<byte> =
        let safeEncrypt() =
            use cipher =
                new RijndaelManaged(
                    Key = keyBytes,
                    Mode = CipherMode.ECB,
                    Padding = PaddingMode.None
                )

            let rec innerEncrypt (x: int) (state: array<byte>) =
                if x >= data.Length then
                    state
                else
                    let nextKeyStreamByte() : byte =
                        let updateCounter() : int =
                            let encryptCounter() : unit =
                                let encryptedCounter =
                                    cipher
                                        .CreateEncryptor()
                                        .TransformFinalBlock(
                                            counter,
                                            0,
                                            BlockSize
                                        )

                                Array.blit
                                    encryptedCounter
                                    0
                                    counterOut
                                    0
                                    BlockSize

                            let increamentCounter() : unit =
                                let rec innerIncreament pos (carry: int) =
                                    if pos < 0 then
                                        ()
                                    else
                                        let increamentedByte =
                                            (int(counter.[pos]) &&& 0xff)
                                            + carry

                                        let carry: int =
                                            if x > 0xff then
                                                1
                                            else
                                                0

                                        counter.[pos] <- byte increamentedByte
                                        innerIncreament(pos - 1) carry

                                innerIncreament(counter.Length - 1) 1

                            encryptCounter()
                            increamentCounter()

                            0

                        let keyStreamPointer =
                            match keyStreamPointerOpt with
                            | None -> updateCounter()
                            | Some keyStreamPointer ->
                                if keyStreamPointer >= BlockSize then
                                    updateCounter()
                                else
                                    keyStreamPointer

                        keyStreamPointerOpt <- Some(keyStreamPointer + 1)
                        counterOut.[keyStreamPointer]

                    let nextByte = (data.[x] ^^^ nextKeyStreamByte())
                    innerEncrypt(x + 1) (Array.append state [| nextByte |])

            innerEncrypt 0 Array.empty

        lock encryptLock safeEncrypt
