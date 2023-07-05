using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Attributes;

using System.Security.Cryptography;

using BenchmarkingAndOptimization;
using BenchmarkDotNet.Diagnostics.Windows.Configs;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;

BenchmarkRunner.Run<BenchTheMark>();

[MemoryDiagnoser]
[InliningDiagnoser(true, true)]
[Config(typeof(Config))]
[SimpleJob(runtimeMoniker: RuntimeMoniker.Net80)]
public class BenchTheMark
{
    private class Config : ManualConfig
    {
        public Config()
        {
            AddColumn(
                StatisticColumn.P50,
                StatisticColumn.P90,
                StatisticColumn.P95);
        }
    }

    const string _password = "Klartext-Kennwort";
    const int _rounds = 5000;
    const string _salt = "0f8e113ec6398b9315ff4af3ac5cd625";
    private HashAlgorithm _algorithm;
    private byte[] _saltBytes;

    [GlobalSetup]
    public void Setup()
    {
        _algorithm = SHA1.Create();
        _saltBytes = Convert.FromHexString(_salt);
    }

    [Benchmark(Baseline = true)]
    public HashedPassword Naive() 
        => Hasher.SAPPasswordAlgorithmNaive(_password, _saltBytes, _algorithm, _rounds);

    [Benchmark]
    public HashedPassword NoToArray() 
        => Hasher.SAPPasswordAlgorithmAvoidToArray(_password, _saltBytes, _algorithm, _rounds);

    [Benchmark]
    public HashedPassword ArrayPooling() 
        => Hasher.SAPPasswordAlgorithmArrayPooling(_password, _saltBytes, _algorithm, _rounds);

    [Benchmark]
    public HashedPassword ArrayPoolingReuseBuffers() 
        => Hasher.SAPPasswordAlgorithmReuseHashBuffers(_password, _saltBytes, _algorithm, _rounds);

    [Benchmark]
    public HashedPassword Stackallocs() 
        => Hasher.SAPPasswordAlgorithmStackAllocation(_password, _saltBytes, _algorithm, _rounds);

    [Benchmark]
    public HashedPassword Unroll() 
        => Hasher.SAPPasswordAlgorithmStackAllocationUnroll(_password, _saltBytes, _algorithm, _rounds);
}