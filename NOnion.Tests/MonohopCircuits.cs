using Microsoft.FSharp.Core;
using System;
using System.Diagnostics;
using System.Net;
using System.Linq;
using System.Threading.Tasks;

using NUnit.Framework;

using NOnion.Network;
using NOnion.Http;
using NOnion.Directory;
using NOnion.Utility;

namespace NOnion.Tests
{
    public class MonohopCircuits
    {
        [SetUp]
        public void Init()
        {
            TorLogger.Init(TestContext.Progress.WriteLine);
        }

        /* It's possible that the router returned by GetRandomFallbackDirectory or
         * GetRandomRoutersForDirectoryBrowsing be inaccessable so we need to continue
         * retrying if an exceptions happened to make sure the issues are not related
         * to the router we randomly chose
         */
        private const int TestsRetryCount = 10;

        private async Task CreateMonoHopCircuit()
        {
            var fallbackDirectory = FallbackDirectorySelector.GetRandomFallbackDirectory();
            using TorGuard guard = await TorGuard.NewClientAsync(fallbackDirectory);
            var circuit = new TorCircuit(guard);
            var circuitId = await circuit.CreateAsync(CircuitNodeDetail.FastCreate);
            TestContext.Progress.WriteLine("Created circuit, Id: {0}", circuitId);

            Assert.Greater(circuitId, 0);
        }

        [Test]
        [Retry(TestsRetryCount)]
        public void CanCreateMonohopCircuit()
        {
            Assert.DoesNotThrowAsync(CreateMonoHopCircuit);
        }

        private async Task CreateDirectoryStreamOverMonohopCircuit()
        {
            var fallbackDirectory = FallbackDirectorySelector.GetRandomFallbackDirectory();
            using TorGuard guard = await TorGuard.NewClientAsync(fallbackDirectory);
            var circuit = new TorCircuit(guard);
            var stream = new TorStream(circuit);

            await circuit.CreateAsync(CircuitNodeDetail.FastCreate);
            await stream.ConnectToDirectoryAsync();
        }

        [Test]
        [Retry(TestsRetryCount)]
        public void CanCreateDirectoryStreamOverMonohopCircuit()
        {
            Assert.DoesNotThrowAsync(CreateDirectoryStreamOverMonohopCircuit);
        }

        private async Task ReceiveConsensusOverMonohopCircuit(bool acceptCompressed)
        {
            var fallbackDirectory = FallbackDirectorySelector.GetRandomFallbackDirectory();
            using TorGuard guard = await TorGuard.NewClientAsync(fallbackDirectory);
            var circuit = new TorCircuit(guard);
            var stream = new TorStream(circuit);

            await circuit.CreateAsync(CircuitNodeDetail.FastCreate);
            await stream.ConnectToDirectoryAsync();

            var httpClient = new TorHttpClient(stream, fallbackDirectory.Address.ToString());
            var response = await httpClient.GetAsStringAsync("/tor/status-vote/current/consensus", acceptCompressed);

            Assert.That(response.Contains("network-status-version"));
        }

        [Test]
        [Retry(TestsRetryCount)]
        public void CanReceiveConsensusOverMonohopCircuit()
        {
            Assert.DoesNotThrowAsync(async () => await ReceiveConsensusOverMonohopCircuit(false));
        }

        [Test]
        [Retry(TestsRetryCount)]
        public void CanReceiveCompressedConsensusOverMonohopCircuit()
        {
            Assert.DoesNotThrowAsync(async () => await ReceiveConsensusOverMonohopCircuit(true));
        }

        private async Task ReceiveCompressedConsensusOverNonFastMonohopCircuit()
        {
            var node = (CircuitNodeDetail.Create)(await CircuitHelper.GetRandomRoutersForDirectoryBrowsingWithRetry()).First();
            using TorGuard guard = await TorGuard.NewClientAsync(node.EndPoint);
            var circuit = new TorCircuit(guard);
            var stream = new TorStream(circuit);

            await circuit.CreateAsync(node);
            await stream.ConnectToDirectoryAsync();

            var httpClient = new TorHttpClient(stream, node.EndPoint.Address.ToString());
            var response = await httpClient.GetAsStringAsync("/tor/status-vote/current/consensus", false);

            Assert.That(response.Contains("network-status-version"));
        }

        [Test]
        [Retry(TestsRetryCount)]
        public void CanReceiveCompressedConsensusOverNonFastMonohopCircuit()
        {
            Assert.DoesNotThrowAsync(ReceiveCompressedConsensusOverNonFastMonohopCircuit);
        }
    }
}
