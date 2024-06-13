using Microsoft.FSharp.Core;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

using NOnion.Network;
using NOnion.Http;
using NOnion.Cells.Relay;
using NOnion.Directory;
using NOnion.Tests.Utility;
using NOnion.Services;

namespace NOnion.Tests
{
    public class HiddenServicesTests
    {
        /* It's possible that the router returned by GetRandomFallbackDirectory or
         * GetRandomRoutersForDirectoryBrowsing be inaccessable so we need to continue
         * retrying if an exceptions happened to make sure the issues are not related
         * to the router we randomly chose
         */
        private const int TestsRetryCount = 10;

        private async Task CreateIntroductionCircuit()
        {
            var node = (CircuitNodeDetail.Create)(await CircuitHelper.GetRandomRoutersForDirectoryBrowsingWithRetry()).First();
            using TorGuard guard = await TorGuard.NewClientAsync(node.EndPoint);
            var circuit = new TorCircuit(guard);

            await circuit.CreateAsync(CircuitNodeDetail.FastCreate);
            await circuit.RegisterAsIntroductionPointAsync(FSharpOption<AsymmetricCipherKeyPair>.None, StubCallback, DisconnectionCallback);
        }

        private Task StubCallback(RelayIntroduce _)
        {
            return Task.CompletedTask;
        }

        private void DisconnectionCallback() { }

        [Test]
        [Retry(TestsRetryCount)]
        public void CanCreateIntroductionCircuit()
        {
            Assert.DoesNotThrowAsync(CreateIntroductionCircuit);
        }


        private async Task CreateRendezvousCircuit()
        {
            var array = new byte[Constants.RendezvousCookieLength];
            RandomNumberGenerator.Create().GetNonZeroBytes(array);

            var nodes = await CircuitHelper.GetRandomRoutersForDirectoryBrowsingWithRetry(2);
            using TorGuard guard = await TorGuard.NewClientAsync(((CircuitNodeDetail.Create)nodes[0]).EndPoint);
            var circuit = new TorCircuit(guard);

            await circuit.CreateAsync(nodes[0]);
            await circuit.ExtendAsync(nodes[1]);
            await circuit.RegisterAsRendezvousPointAsync(array);
        }


        [Test]
        [Retry(TestsRetryCount)]
        public void CanCreateRendezvousCircuit()
        {
            Assert.DoesNotThrowAsync(CreateRendezvousCircuit);
        }

        private async Task<int> ReadExact(TorStream stream, byte[] buffer, int off, int len)
        {
            if (len - off <= 0) return 0;

            var bytesRead = await stream.ReadAsync(buffer, off, len - off);

            if (bytesRead == 0 || bytesRead == -1)
                throw new Exception("Not enough data");

            return bytesRead + await ReadExact(stream, buffer, off + bytesRead, len);
        }

        public async Task BrowseFacebookOverHS()
        {
            TorDirectory directory = await TorDirectory.BootstrapAsync(FallbackDirectorySelector.GetRandomFallbackDirectory(), new DirectoryInfo(Path.GetTempPath()));

            var client = await TorServiceClient.ConnectAsync(directory, "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion");
            var httpClient = new TorHttpClient(client.GetStream(), "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion");

            try
            {
                await httpClient.GetAsStringAsync("/", false);
            }
            catch (UnsuccessfulHttpResponseException)
            {
                // Ignore non-200 Http response status codes
                // The fact that we are receieving an http response means we are connected
            }
        }

        [Test]
        [Retry(TestsRetryCount)]
        public void CanBrowseFacebookOverHS()
        {
            Assert.DoesNotThrowAsync(BrowseFacebookOverHS);
        }

        public async Task BrowseFacebookOverHSWithTLS()
        {
            TorDirectory directory = await TorDirectory.BootstrapAsync(FallbackDirectorySelector.GetRandomFallbackDirectory(), new DirectoryInfo(Path.GetTempPath()));

            var client = await TorServiceClient.ConnectAsync(directory, "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion:443");

            var sslStream = new SslStream(client.GetStream(), true, (sender, cert, chain, sslPolicyErrors) => true);
            await sslStream.AuthenticateAsClientAsync(string.Empty, null, SslProtocols.Tls12, false);

            var httpClientOverSslStream = new TorHttpClient(sslStream, "www.facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion");

            try
            {
                var facebookResponse = await httpClientOverSslStream.GetAsStringAsync("/", false);
                Assert.That(facebookResponse.Contains("<html"), "Response from facebook was invalid.");
            }
            catch (UnsuccessfulHttpResponseException)
            {
                // Ignore non-200 Http response status codes
                // The fact that we are receieving an http response means we are connected
            }
        }

        [Test]
        [Retry(TestsRetryCount)]
        public void CanBrowseFacebookOverHSWithTLS()
        {
            Assert.DoesNotThrowAsync(BrowseFacebookOverHSWithTLS);
        }

        private async Task<(TorDirectory, TorServiceHost)> BootstrapDirectoryAndStartHost()
        {
            int descriptorUploadRetryLimit = 2;

            TorDirectory directory = await TorDirectory.BootstrapAsync(FallbackDirectorySelector.GetRandomFallbackDirectory(), new DirectoryInfo(Path.GetTempPath()));

            TorLogger.Log("Finished bootstraping");

            SecureRandom random = new SecureRandom();
            Ed25519KeyPairGenerator kpGen = new Ed25519KeyPairGenerator();
            kpGen.Init(new Ed25519KeyGenerationParameters(random));
            Ed25519PrivateKeyParameters masterPrivateKey = (Ed25519PrivateKeyParameters)kpGen.GenerateKeyPair().Private;

            TorServiceHost host = new TorServiceHost(directory, descriptorUploadRetryLimit, TestsRetryCount, FSharpOption<Ed25519PrivateKeyParameters>.Some(masterPrivateKey));
            await host.StartAsync();

            TorLogger.Log("Finished starting HS host");

            return (directory, host);
        }

        public async Task EstablishAndCommunicateOverHSConnectionOnionStyle()
        {
            (var directory, var host) = await BootstrapDirectoryAndStartHost();

            var dataToSendAndReceive = new byte[] { 1, 2, 3, 4 };

            var serverSide =
                Task.Run(async () => {
                    var stream = await host.AcceptClientAsync();
                    var bytesToSendWithLength = BitConverter.GetBytes(dataToSendAndReceive.Length).Concat(dataToSendAndReceive).ToArray();
                    await stream.WriteAsync(bytesToSendWithLength, 0, bytesToSendWithLength.Length);
                    await stream.EndAsync();
                });

            var clientSide =
                Task.Run(async () => {
                    var client = await TorServiceClient.ConnectAsync(directory, host.ExportUrl());
                    var stream = client.GetStream();
                    var lengthBytes = new byte[sizeof(int)];
                    await ReadExact(stream, lengthBytes, 0, lengthBytes.Length);
                    var length = BitConverter.ToInt32(lengthBytes);
                    var buffer = new byte[length];
                    await ReadExact(stream, buffer, 0, buffer.Length);

                    CollectionAssert.AreEqual(buffer, dataToSendAndReceive);
                });

            await TaskUtils.WhenAllFailFast(serverSide, clientSide);

            ((IDisposable) host).Dispose();
        }

        [Test]
        [Retry(TestsRetryCount)]
        public void CanEstablishAndCommunicateOverHSConnectionOnionStyle()
        {
            Assert.DoesNotThrowAsync(EstablishAndCommunicateOverHSConnectionOnionStyle);
        }

#if NET6_0_OR_GREATER
        [Test]
        [Retry(TestsRetryCount)]
        public void CanConnectToHiddenServiceUsingTorClient()
        {
            Assert.DoesNotThrowAsync(ConnectToHiddenServiceUsingTorClient);
        }

        private async Task ConnectToHiddenServiceUsingTorClient()
        {
            (_, var host) = await BootstrapDirectoryAndStartHost();

            var stringToSendAndReceive =
                "We are using tor!";

            var serverSide =
                Task.Run(async () => {
                    var stream = await host.AcceptClientAsync();

                    var httpResponse =
                        "HTTP/1.1 200 OK\r\n" +
                        "Server: NOnion\r\n" +
                        $"Content-Length: {stringToSendAndReceive.Length}\r\n" +
                        "Connection: close\r\n" +
                        "Content-Type: text/plain" +
                        "\r\n" +
                        "\r\n" +
                        stringToSendAndReceive +
                        "\r\n";
                    var httpResponseBytes =
                        Encoding.ASCII.GetBytes(httpResponse);

                    await stream.WriteAsync(httpResponseBytes, 0, httpResponseBytes.Length);
                    await stream.EndAsync();
                });

            var clientSide =
                Task.Run(async () => {
                    var handler = new HttpClientHandler
                    {
                        Proxy = new WebProxy(new Uri("socks5://localhost:9050"))
                    };

                    TestContext.Progress.WriteLine("Trying to connect to hidden service...");
                    using (handler)
                    using (var httpClient = new HttpClient(handler))
                    {
                        // Sometimes tor client takes a while to bootstrap and stalls
                        // the request.
                        httpClient.Timeout = TimeSpan.FromMinutes(20);
                        var result = await httpClient.GetStringAsync("http://" + host.ExportUrl());
                        Assert.AreEqual(result, stringToSendAndReceive);
                    }
                }
            );

            await TaskUtils.WhenAllFailFast(serverSide, clientSide);

            ((IDisposable)host).Dispose();
        }
#endif
    }
}

