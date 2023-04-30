using NOnion.Crypto;
using NOnion.Utility;
using NUnit.Framework;

namespace NOnion.Tests
{
    public class CryptoTests
    {
        private readonly string[] SecKeys = new string[] {
            "26c76712d89d906e6672dafa614c42e5cb1caac8c6568e4d2493087db51f0d36",
            "fba7a5366b5cb98c2667a18783f5cf8f4f8d1a2ce939ad22a6e685edde85128d",
            "67e3aa7a14fac8445d15e45e38a523481a69ae35513c9e4143eb1c2196729a0e",
            "d51385942033a76dc17f089a59e6a5a7fe80d9c526ae8ddd8c3a506b99d3d0a6",
            "5c8eac469bb3f1b85bc7cd893f52dc42a9ab66f1b02b5ce6a68e9b175d3bb433",
            "eda433d483059b6d1ff8b7cfbd0fe406bfb23722c8f3c8252629284573b61b86",
            "4377c40431c30883c5fbd9bc92ae48d1ed8a47b81d13806beac5351739b5533d",
            "c6bbcce615839756aed2cc78b1de13884dd3618f48367a17597a16c1cd7a290b",
            "c6bbcce615839756aed2cc78b1de13884dd3618f48367a17597a16c1cd7a290b",
            "c6bbcce615839756aed2cc78b1de13884dd3618f48367a17597a16c1cd7a290b"
        };

        private readonly string[] PubKeys = new string[] {
            "c2247870536a192d142d056abefca68d6193158e7c1a59c1654c954eccaff894",
            "1519a3b15816a1aafab0b213892026ebf5c0dc232c58b21088d88cb90e9b940d",
            "081faa81992e360ea22c06af1aba096e7a73f1c665bc8b3e4e531c46455fd1dd",
            "73cfa1189a723aad7966137cbffa35140bb40d7e16eae4c40b79b5f0360dd65a",
            "66c1a77104d86461b6f98f73acf3cd229c80624495d2d74d6fda1e940080a96b",
            "d21c294db0e64cb2d8976625786ede1d9754186ae8197a64d72f68c792eecc19",
            "c4d58b4cf85a348ff3d410dd936fa460c4f18da962c01b1963792b9dcc8a6ea6",
            "95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a",
            "95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a",
            "95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a"
        };

        private readonly string[] BlindingFactors = new string[] {
            "54a513898b471d1d448a2f3c55c1de2c0ef718c447b04497eeb999ed32027823",
            "831e9b5325b5d31b7ae6197e9c7a7baf2ec361e08248bce055908971047a2347",
            "ac78a1d46faf3bfbbdc5af5f053dc6dc9023ed78236bec1760dadfd0b2603760",
            "f9c84dc0ac31571507993df94da1b3d28684a12ad14e67d0a068aba5c53019fc",
            "b1fe79d1dec9bc108df69f6612c72812755751f21ecc5af99663b30be8b9081f",
            "81f1512b63ab5fb5c1711a4ec83d379c420574aedffa8c3368e1c3989a3a0084",
            "97f45142597c473a4b0e9a12d64561133ad9e1155fe5a9807fe6af8a93557818",
            "3f44f6a5a92cde816635dfc12ade70539871078d2ff097278be2a555c9859cd0",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "1111111111111111111111111111111111111111111111111111111111111111"
        };

        private readonly string[] BlindedSecKeys = new string[] {
            "293c3acff4e902f6f63ddc5d5caa2a57e771db4f24de65d4c28df3232f47fa01171d43f24e3f53e70ec7ac280044ac77d4942dee5d6807118a59bdf3ee647e89",
            "38b88f9f9440358da544504ee152fb475528f7c51c285bd1c68b14ade8e29a07b8ceff20dfcf53eb52b891fc078c934efbf0353af7242e7dc51bb32a093afa29",
            "4d03ce16a3f3249846aac9de0a0075061495c3b027248eeee47da4ddbaf9e0049217f52e92797462bd890fc274672e05c98f2c82970d640084781334aae0f940",
            "51d7db01aaa0d937a9fd7c8c7381445a14d8fa61f43347af5460d7cd8fda9904509ecee77082ce088f7c19d5a00e955eeef8df6fa41686abc1030c2d76807733",
            "1f76cab834e222bd2546efa7e073425680ab88df186ff41327d3e40770129b00b57b95a440570659a440a3e4771465022a8e67af86bdf2d0990c54e7bb87ff9a",
            "c23588c23ee76093419d07b27c6df5922a03ac58f96c53671456a7d1bdbf560ec492fc87d5ec2a1b185ca5a40541fdef0b1e128fd5c2380c888bfa924711bcab",
            "3ed249c6932d076e1a2f6916975914b14e8c739da00992358b8f37d3e790650691b4768f8e556d78f4bdcb9a13b6f6066fe81d3134ae965dc48cd0785b3af2b8",
            "288cbfd923cb286d48c084555b5bdd06c05e92fb81acdb45271367f57515380e053d9c00c81e1331c06ab50087be8cfc7dc11691b132614474f1aa9c2503cccd",
            "e5cd03eb4cc456e11bc36724b558873df0045729b22d8b748360067a7770ac02053d9c00c81e1331c06ab50087be8cfc7dc11691b132614474f1aa9c2503cccd",
            "2cf7ed8b163f5af960d2fc62e1883aa422a6090736b4f18a5456ddcaf78ede0c053d9c00c81e1331c06ab50087be8cfc7dc11691b132614474f1aa9c2503cccd"
        };

        private readonly string[] BlindedPubKeys = new string[] {
            "1fc1fa4465bd9d4956fdbdc9d3acb3c7019bb8d5606b951c2e1dfe0b42eaeb41",
            "1cbbd4a88ce8f165447f159d9f628ada18674158c4f7c5ead44ce8eb0fa6eb7e",
            "c5419ad133ffde7e0ac882055d942f582054132b092de377d587435722deb028",
            "3e08d0dc291066272e313014bfac4d39ad84aa93c038478a58011f431648105f",
            "59381f06acb6bf1389ba305f70874eed3e0f2ab57cdb7bc69ed59a9b8899ff4d",
            "2b946a484344eb1c17c89dd8b04196a84f3b7222c876a07a4cece85f676f87d9",
            "c6b585129b135f8769df2eba987e76e089e80ba3a2a6729134d3b28008ac098e",
            "0eefdc795b59cabbc194c6174e34ba9451e8355108520554ec285acabebb34ac",
            "312404d06a0a9de489904b18d5233e83a50b225977fa8734f2c897a73c067952",
            "952a908a4a9e0e5176a2549f8f328955aca6817a9fdc59e3acec5dec50838108"
        };

        [Test]
        public void CanCalculateBlindedKeys ()
        {
            for (int i = 0; i < SecKeys.Length; i++)
            {
                var pubKey = Hex.ToByteArray(PubKeys[i]);
                var secKey = Hex.ToByteArray(SecKeys[i]);
                var blindingFactor = Hex.ToByteArray(BlindingFactors[i]);
                var expectedBlindedPubKey = Hex.ToByteArray(BlindedPubKeys[i]);
                var expectedBlindedSecKey = Hex.ToByteArray(BlindedSecKeys[i]);

                var calculatedBlindedPubKey =
                    HiddenServicesCipher.CalculateBlindedPublicKey(blindingFactor, pubKey);

                CollectionAssert.AreEqual(expectedBlindedPubKey, calculatedBlindedPubKey, "Blinded public key swas invalid");

                var calculatedBlindedSecKey =
                    HiddenServicesCipher.CalculateExpandedBlindedPrivateKey(blindingFactor, secKey);

                CollectionAssert.AreEqual(expectedBlindedSecKey, calculatedBlindedSecKey, "Blinded secret key was invalid");
            }
        }
    }
}
