using Microsoft.FSharp.Core;
using System.IO;
using System.Threading.Tasks;

using NUnit.Framework;

using NOnion.Client;

namespace NOnion.Tests
{
    public class TorClientTests
    {
        private async Task BootstrapWithGithub()
        {
            await TorClient.BootstrapWithGithubAsync(FSharpOption<DirectoryInfo>.None);
        }

        [Test]
        public void CanBootstrapWithGithub()
        {
            Assert.DoesNotThrowAsync(BootstrapWithGithub);
        }
        
        private async Task BootstrapWithEmbeddedList()
        {
            await TorClient.BootstrapWithEmbeddedListAsync(FSharpOption<DirectoryInfo>.None);
        }

        [Test]
        public void CanBootstrapWithEmbeddedList()
        {
            Assert.DoesNotThrowAsync(BootstrapWithEmbeddedList);
        }
        
        private async Task CreateCircuit()
        {
            using TorClient client = await TorClient.BootstrapWithEmbeddedListAsync(FSharpOption<DirectoryInfo>.None);
            await client.CreateCircuitAsync(3, CircuitPurpose.Unknown, FSharpOption<Network.CircuitNodeDetail>.None);
        }

        [Test]
        public void CanCreateCircuit()
        {
            Assert.DoesNotThrowAsync(CreateCircuit);
        }
    }
}
