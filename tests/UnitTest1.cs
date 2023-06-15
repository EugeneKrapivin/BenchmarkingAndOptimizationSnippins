using BenchmarkingAndOptimization;

using System.Collections.Generic;
using System.Security.Cryptography;

namespace tests
{
    public class Tests
    {
        const string password = "Klartext-Kennwort";
        const int rounds = 5000;
        const string salt = "0f8e113ec6398b9315ff4af3ac5cd625";

        [Test]
        public void Test_Correctness()
        {
            var result = Hasher.SAPPasswordAlgorithmNaive(password, Convert.FromHexString(salt), SHA1.Create(), rounds);
            Assert.That(Convert.ToHexString(result.PasswordHash).ToLower(), Is.EqualTo("ca9c3dedfc17a8bd76346b1780e0f284db57572a"));

            result = Hasher.SAPPasswordAlgorithmAvoidToArray(password, Convert.FromHexString(salt), SHA1.Create(), rounds);
            Assert.That(Convert.ToHexString(result.PasswordHash).ToLower(), Is.EqualTo("ca9c3dedfc17a8bd76346b1780e0f284db57572a"));

            result = Hasher.SAPPasswordAlgorithmArrayPooling(password, Convert.FromHexString(salt), SHA1.Create(), rounds);
            Assert.That(Convert.ToHexString(result.PasswordHash).ToLower(), Is.EqualTo("ca9c3dedfc17a8bd76346b1780e0f284db57572a"));

            result = Hasher.SAPPasswordAlgorithmReuseHashBuffers(password, Convert.FromHexString(salt), SHA1.Create(), rounds);
            Assert.That(Convert.ToHexString(result.PasswordHash).ToLower(), Is.EqualTo("ca9c3dedfc17a8bd76346b1780e0f284db57572a"));

            result = Hasher.SAPPasswordAlgorithmStackAllocation(password, Convert.FromHexString(salt), SHA1.Create(), rounds);
            Assert.That(Convert.ToHexString(result.PasswordHash).ToLower(), Is.EqualTo("ca9c3dedfc17a8bd76346b1780e0f284db57572a"));
        }
    }
}