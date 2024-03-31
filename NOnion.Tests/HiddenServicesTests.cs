using Microsoft.FSharp.Core;
using System;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Threading.Tasks;

using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

using NOnion.Network;
using NOnion.Http;
using NOnion.Cells.Relay;
using NOnion.Client;
using NOnion.Directory;
using NOnion.Tests.Utility;
using NOnion.Services;

namespace NOnion.Tests
{
    public class HiddenServicesTests
    {
        [OneTimeSetUp]
        public void Init()
        {
            cachePath =
                new DirectoryInfo(
                    Path.Combine(
                        Path.GetTempPath(),
                        Path.GetFileNameWithoutExtension(
                            Path.GetRandomFileName()
                        )
                    )
                );
            cachePath.Create();
        }

        private DirectoryInfo cachePath = null;
        
        /* It's possible that the router returned by GetRandomFallbackDirectory or
         * GetRandomRoutersForDirectoryBrowsing be inaccessable so we need to continue
         * retrying if an exceptions happened to make sure the issues are not related
         * to the router we randomly chose
         */
        private const int TestsRetryCount = 10;

        private async Task CreateIntroductionCircuit()
        {
            using TorClient torClient = await TorClient.BootstrapWithGitlabAsync(cachePath);
            var circuit = await torClient.CreateCircuitAsync(1, CircuitPurpose.Unknown, FSharpOption<CircuitNodeDetail>.None);
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

            using TorClient torClient = await TorClient.BootstrapWithGitlabAsync(cachePath);
            var circuit = await torClient.CreateCircuitAsync(2, CircuitPurpose.Unknown, FSharpOption<CircuitNodeDetail>.None);
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
            using TorClient torClient = await TorClient.BootstrapWithGitlabAsync(cachePath);

            var serviceClient = await TorServiceClient.ConnectAsync(torClient, "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion");
            var stream = await serviceClient.GetStreamAsync();
            var httpClient = new TorHttpClient(stream, "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion");

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
            using TorClient torClient = await TorClient.BootstrapWithGitlabAsync(cachePath);
            
            var serviceClient = await TorServiceClient.ConnectAsync(torClient, "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion:443");
            var stream = await serviceClient.GetStreamAsync();
            var sslStream = new SslStream(stream, true, (sender, cert, chain, sslPolicyErrors) => true);
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

        public async Task EstablishAndCommunicateOverHSConnectionOnionStyle()
        {
            using TorClient torClient = await TorClient.BootstrapWithGitlabAsync(cachePath);
            
            TorLogger.Log("Finished bootstraping");

            SecureRandom random = new SecureRandom();
            Ed25519KeyPairGenerator kpGen = new Ed25519KeyPairGenerator();
            kpGen.Init(new Ed25519KeyGenerationParameters(random));
            Ed25519PrivateKeyParameters masterPrivateKey = (Ed25519PrivateKeyParameters)kpGen.GenerateKeyPair().Private;

            TorServiceHost host = new TorServiceHost(torClient, FSharpOption<Ed25519PrivateKeyParameters>.Some(masterPrivateKey));
            await host.StartAsync();

            TorLogger.Log("Finished starting HS host");

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
                    var serviceClient = await TorServiceClient.ConnectAsync(torClient, host.ExportUrl());
                    var stream = await serviceClient.GetStreamAsync();
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
    }
}

