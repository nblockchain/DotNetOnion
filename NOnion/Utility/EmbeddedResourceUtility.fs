namespace NOnion.Utility

open System
open System.IO
open System.Reflection

module EmbeddedResourceUtility =

    // Code from https://github.com/nblockchain/geewallet/blob/428cb77d21dba20fc38c7ea032003c5861aac950/src/GWallet.Backend/Config.fs#L156
    let ExtractEmbeddedResourceFileContents(resourceName: string) : string =
        let assembly = Assembly.GetExecutingAssembly()
        let ress = String.Join(";", assembly.GetManifestResourceNames())

        let fullNameOpt =
            assembly.GetManifestResourceNames()
            |> Seq.filter(fun aResourceName ->
                aResourceName = resourceName
                || aResourceName.EndsWith("." + resourceName)
            )
            |> Seq.tryExactlyOne

        match fullNameOpt with
        | Some fullName ->
            use stream = assembly.GetManifestResourceStream fullName

            if isNull stream then
                failwithf
                    "Embedded resource %s (%s) not found in assembly %s"
                    resourceName
                    fullName
                    assembly.FullName

            use reader = new StreamReader(stream)
            reader.ReadToEnd()
        | None ->
            failwithf
                "Embedded resource %s not found at all in assembly %s (resource names: %s)"
                resourceName
                assembly.FullName
                ress
