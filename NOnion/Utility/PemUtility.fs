namespace NOnion.Utility

open System.IO

open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.OpenSsl
open Org.BouncyCastle.Security

module PemUtility =
    let GetRsaKeyParametersFromPem(pem: string) =
        use stringReader = new StringReader(pem)
        use pemReader = new PemReader(stringReader)
        let publicKey = pemReader.ReadObject() :?> AsymmetricKeyParameter
        publicKey :?> RsaKeyParameters

    let GetRsaParametersFromPem(pem: string) =
        use stringReader = new StringReader(pem)
        use pemReader = new PemReader(stringReader)
        let publicKey = pemReader.ReadObject() :?> AsymmetricKeyParameter

        let rsaParams =
            DotNetUtilities.ToRSAParameters(publicKey :?> RsaKeyParameters)

        rsaParams

    let PemToByteArray(pem: string) =
        use stringReader = new StringReader(pem)
        use pemReader = new PemReader(stringReader)
        pemReader.ReadPemObject().Content
