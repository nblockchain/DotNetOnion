using NUnit.Framework;
using NOnion.Crypto;
using NOnion.Utility;

namespace NOnion.Tests
{

    public class MessageDigest
    {
        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void CanCalculateRunningDigestOver4ByteArrays()
        {
            var digest = new TorMessageDigest();

            byte[] plainText1 =
                Hex.ToByteArray("6bc1bee22e409f96e93d7e117393172a");
            byte[] expectedDigest1 =
                Hex.ToByteArray("2137B53FEF34D0D31EC388C3966EDE215F50D07B");
            digest.Update(plainText1, 0, plainText1.Length);
            byte[] computedDigest1 =
                digest.GetDigestBytes();
            CollectionAssert.AreEqual(expectedDigest1, computedDigest1);

            byte[] plainText2 =
                Hex.ToByteArray("ae2d8a571e03ac9c9eb76fac45af8e51");
            byte[] expectedDigest2 =
                Hex.ToByteArray("0613AF950ACADBB268FB9B7D1B58F3EC5CA57101");
            digest.Update(plainText2, 0, plainText2.Length);
            byte[] computedDigest2 =
                digest.GetDigestBytes();
            CollectionAssert.AreEqual(expectedDigest2, computedDigest2);

            byte[] plainText3 =
                Hex.ToByteArray("30c81c46a35ce411e5fbc1191a0a52ef");
            byte[] expectedDigest3 =
                Hex.ToByteArray("C683BFA46B8D3688481EA36E8F11453A4AEFE71C");
            digest.Update(plainText3, 0, plainText3.Length);
            byte[] computedDigest3 =
                digest.GetDigestBytes();
            CollectionAssert.AreEqual(expectedDigest3, computedDigest3);

            byte[] plainText4 =
                Hex.ToByteArray("f69f2445df4f9b17ad2b417be66c3710");
            byte[] expectedDigest4 =
                Hex.ToByteArray("E0106285E6FF2DFAD052BE9491247BCA7133D540");
            digest.Update(plainText4, 0, plainText4.Length);
            byte[] computedDigest4 =
                digest.GetDigestBytes();
            CollectionAssert.AreEqual(expectedDigest4, computedDigest4);
        }

        [Test]
        public void CanPeekDigestWithoutAffectingTheRunningDigest()
        {
            var digest = new TorMessageDigest();

            byte[] plainText1 =
                Hex.ToByteArray("6bc1bee22e409f96e93d7e117393172a");
            byte[] computedDigest1 =
                digest.PeekDigest(plainText1, 0, plainText1.Length);
            
            digest.Update(plainText1, 0, plainText1.Length);
            byte[] computedDigest1_2 =
                digest.GetDigestBytes();
            CollectionAssert.AreEqual(computedDigest1, computedDigest1_2);
        }

    }
}