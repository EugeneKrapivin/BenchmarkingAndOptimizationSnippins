using BenchmarkDotNet.Attributes.Jobs;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

using BenchmarkingAndOptimization;

using System.Security.Cryptography;
using BenchmarkDotNet.Jobs;

BenchmarkRunner.Run<BenchTheMark>();

[MemoryDiagnoser]
[SimpleJob(runtimeMoniker: RuntimeMoniker.Net70, baseline: true)]
[SimpleJob(runtimeMoniker: RuntimeMoniker.Net80)]
public class BenchTheMark
{
    const string password = "Klartext-Kennwort";
    const int rounds = 5000;
    const string salt = "0f8e113ec6398b9315ff4af3ac5cd625";
    private Hasher _hasher = null!;
    private HashAlgorithm _algorithm;
    private byte[] _salt;

    [GlobalSetup]
    public void Setup()
    {
        _hasher = new Hasher();
        _algorithm = SHA1.Create();
        _salt = Convert.FromHexString(salt);
    }

    [Benchmark(Baseline = true)]
    public HashedPassword Naive() => _hasher.SAPPasswordAlgorithmNaive(password, _salt, _algorithm, rounds);

    [Benchmark]
    public HashedPassword NoToArray() => _hasher.SAPPasswordAlgorithmAvoidToArray(password, _salt, _algorithm, rounds);
}