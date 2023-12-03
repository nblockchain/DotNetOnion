
NOnion
-------------------------------
[![Build Status](https://github.com/aarani/NOnion/actions/workflows/CI.yml/badge.svg?branch=master&event=push)](https://github.com/aarani/NOnion/actions/workflows/CI.yml)

_Unofficial_ work in progress .NET TOR client library (implemented in F#)

- [How do I add this to my project?](#how-do-i-add-this-to-my-project)
- [Getting Started](#getting-started)
- [Contributing](#contributing)
- [Contributors](https://github.com/aarani/NOnion/graphs/contributors)
- [License](https://github.com/aarani/NOnion/blob/master/LICENSE)

# How do I add this to my project?

Install via NuGet:

## .NET CLI
```
> dotnet add package NOnion
```

## VS Package Manager
```
> Install-Package NOnion
```

# Getting Started (F#)

## Bootstrapping

To utilize the Tor network, start by bootstrapping your directory. This step involves downloading the most recent information about available routers and their identity keys.

To initiate the bootstrapping process, you require a list of initial nodes for communication. In NOnion, there are two methods to obtain this list:
1- [Download from Github](https://github.com/torproject/tor/blob/main/src/app/config/fallback_dirs.inc)
2- Utilize the embedded list in the NOnion binary (Note: this list could potentially be outdated)

Based on what option you choose use one of the following commands to bootstrap a TorClient object:
```
let! torClient = TorClient.AsyncBootstrapWithEmbeddedList None
```
### OR
```
let! torClient = TorClient.AsyncBootstrapWithGithub None
```
## Browsing the web

To route your traffic through Tor, you require a circuit, which consists of multiple hops or routers. NOnion simplifies this process for you. Just specify the desired length of your circuit and use the following command:
```
let hopCount = 3 // any length you want
let! circuit = torClient.AsyncCreateCircuit hopCount Exit None
```
Once the circuit is established, generate a stream to channel your traffic and establish a connection with your intended destination.
```
let address = "google.com" // Hostname you want to connect to
let port = 80 // Port you want to connect it

do!
	stream.ConnectToOutside address port
	|> Async.Ignore
```
Now, utilize the stream just like any other `System.IO.Stream`:
```
do! stream.AsyncWrite [|1uy; 2uy; 3uy; 4uy|]
```

## Connecting to hidden services

To connect to a hidden service using the Tor network, use the folowing command:
```
let onionAddress = "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion"

let! serviceClient = TorServiceClient.Connect torClient onionAddress
let stream = serviceClient.GetStream()
```
Now, utilize the stream just like any other `System.IO.Stream`:
```
do!
    sprintf "GET / HTTP/1.0\r\n\r\n"
    |> System.Text.Encoding.ASCII.GetBytes
    |> stream.AsyncWrite
```
## Hosting a hidden service
Start a hidden service, use the following command:
```
let serviceHost = new TorServiceHost(torClient, None)
do! serviceHost.Start()
```
*Note: use TorServiceHost's `maybeMasterPrivateKey` parameter to supply your existing bouncy castle private key*

Now use the following command to wait for incoming streams/clients:
```
let! incomingStream = serviceHost.AcceptClient()
```
Now, utilize the stream just like any other `System.IO.Stream`.

#### Everything mentioned above can be accomplished in C#. Our test project is also written in C#, so feel free to examine it.
# Contributing

Don't underestimate the power of your contribution - even a small pull request can make a big difference in a small project, so submit yours today!
