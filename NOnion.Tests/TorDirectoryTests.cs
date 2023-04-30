using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using NUnit.Framework;

using NOnion;
using NOnion.Directory;
using NOnion.Network;

namespace NOnion.Tests
{
    public class TorDirectoryTests
    {
        [SetUp]
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

            TorLogger.Init(TestContext.Progress.WriteLine);
        }

        private DirectoryInfo cachePath = null;

        /* It's possible that the router returned by GetRandomFallbackDirectory be inaccessable
         * so we need to continue retrying if an exceptions happened to make sure the issues are
         * not related to the router we randomly chose
         */
        private const int TestRetryCount = 10;

        private async Task BootstrapTorDirectory()
        {
            await TorDirectory.BootstrapAsync(FallbackDirectorySelector.GetRandomFallbackDirectory(), cachePath);
        }

        [Test]
        [Retry(TestRetryCount)]
        public void CanBootstrapTorDirectory()
        {
            Assert.DoesNotThrowAsync(BootstrapTorDirectory);
        }

        private async Task ReturnRandomRouter()
        {
            TorDirectory directory = await TorDirectory.BootstrapAsync(FallbackDirectorySelector.GetRandomFallbackDirectory(), cachePath);
            var (endPoint, router) = await directory.GetRouterAsync(RouterType.Normal);
            Assert.IsTrue(router.IsCreate);
            Assert.IsFalse(((CircuitNodeDetail.Create)router).IdentityKey.All(x => x == 0));
            Assert.IsFalse(((CircuitNodeDetail.Create)router).NTorOnionKey.All(x => x == 0));
            Assert.IsNotNull(((CircuitNodeDetail.Create)router).EndPoint);
            Assert.That(endPoint, Is.EqualTo(((CircuitNodeDetail.Create)router).EndPoint));
        }

        [Test]
        [Retry(TestRetryCount)]
        public void CanReturnRandomRouter()
        {
            Assert.DoesNotThrowAsync(ReturnRandomRouter);
        }
    }
}
