using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using Newtonsoft.Json;
using NUnit.Framework;

using NOnion.Proxy;

namespace NOnion.Tests
{
    internal class TorProxyTests
    {
        private const int MaximumRetry = 3;

        private class TorProjectCheckResult
        {
            [JsonProperty("IsTor")]
            internal bool IsTor { get; set; }

            [JsonProperty("IP")]
            internal string IP { get; set; }
        }

        [Test]
        [Retry(MaximumRetry)]
        public void CanProxyTorProjectExitNodeCheck()
        {
            Assert.DoesNotThrowAsync(ProxyTorProjectExitNodeCheck);
        }

        private async Task ProxyTorProjectExitNodeCheck()
        {
            using (await TorProxy.StartAsync(IPAddress.Loopback, 20000))
            {
                var handler = new HttpClientHandler
                {
                    Proxy = new WebProxy("http://localhost:20000")
                };

                var client = new HttpClient(handler);
                var resultStr = await client.GetStringAsync("https://check.torproject.org/api/ip");
                var result = JsonConvert.DeserializeObject<TorProjectCheckResult>(resultStr);
                Assert.IsTrue(result.IsTor);
            }
        }

        [Test]
        [Retry(MaximumRetry)]
        public void CanProxyHttps()
        {
            Assert.DoesNotThrowAsync(ProxyHttps);
        }

        private async Task ProxyHttps()
        {
            using (await TorProxy.StartAsync(IPAddress.Loopback, 20000))
            {
                var handler = new HttpClientHandler
                {
                    Proxy = new WebProxy("http://localhost:20000")
                };

                var client = new HttpClient(handler);
                var googleResponse = await client.GetAsync("https://google.com");
                Assert.That(googleResponse.StatusCode > 0);
            }
        }

        [Test]
        [Retry(MaximumRetry)]
        public void CanProxyHttp()
        {
            Assert.DoesNotThrowAsync(ProxyHttp);
        }

        private async Task ProxyHttp()
        {
            using (await TorProxy.StartAsync(IPAddress.Loopback, 20000))
            {
                var handler = new HttpClientHandler
                {
                    Proxy = new WebProxy("http://localhost:20000")
                };

                var client = new HttpClient(handler);
                var googleResponse = await client.GetAsync("http://google.com/search?q=Http+Test");
                Assert.That(googleResponse.StatusCode > 0);
            }
        }

        [Test]
        [Retry(MaximumRetry)]
        public void CanProxyHiddenService()
        {
            Assert.DoesNotThrowAsync(ProxyHiddenService);
        }

        private async Task ProxyHiddenService()
        {
            using (await TorProxy.StartAsync(IPAddress.Loopback, 20000))
            {
                var handler = new HttpClientHandler
                {
                    Proxy = new WebProxy("http://localhost:20000"),
                    ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true
                };

                var client = new HttpClient(handler);
                var facebookResponse = await client.GetAsync("https://facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion");
                Assert.That(facebookResponse.StatusCode > 0);
            }
        }
    }
}
