namespace NOnion.Cells

open System.IO

open FSharpx.Collections

open NOnion.Utility.BinaryIO

type Cert =
    {
        Type: byte
        Certificate: array<byte>
    }

type CellCerts =
    {
        Certs: seq<Cert>
    }

    static member Deserialize(reader: BinaryReader) =

        let rec readCertificates certificates remainingCount =
            if remainingCount = 0 then
                certificates
            else
                let certificate =
                    {
                        Cert.Type = reader.ReadByte()
                        Cert.Certificate =
                            ReadBigEndianUInt16 reader
                            |> int
                            |> reader.ReadBytes
                    }

                readCertificates
                    (certificate :: certificates)
                    (remainingCount - 1)

        let certificatesCount = reader.ReadByte() |> int
        let certs = readCertificates List.empty certificatesCount |> Seq.rev

        {
            Certs = certs
        }
        :> ICell

    interface ICell with

        member __.Command = 129uy

        member self.Serialize writer =

            let rec writeCertificates(certificates: seq<Cert>) =
                match Seq.tryHeadTail certificates with
                | None -> ()
                | Some(certificate, nextCertificates) ->
                    writer.Write certificate.Type

                    certificate.Certificate.Length
                    |> uint16
                    |> WriteUInt16BigEndian writer

                    writer.Write certificate.Certificate
                    nextCertificates |> writeCertificates

            self.Certs |> Seq.length |> uint8 |> writer.Write
            writeCertificates self.Certs
