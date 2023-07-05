using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace BenchmarkingAndOptimization;

public record struct HashedPassword(byte[] PasswordHash, byte[] Salt, int Rounds);

public static class Hasher
{
    // SAP ABAP password hashing algorithm gist
    // get clear text password utf8 bytes
    // r_1 = sha(password.salt)
    // r_n = sha(password.r_n-1)

    public static HashedPassword SAPPasswordAlgorithmNaive(string clearText, byte[] salt, HashAlgorithm hasher, int rounds = 1000)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(clearText);

        var buffer = hasher.ComputeHash(passwordBytes.Concat(salt).ToArray());

        for (var i = 1; i < rounds; i++)
        {
            buffer = hasher.ComputeHash(passwordBytes.Concat(buffer).ToArray());
        }

        return new() { PasswordHash = buffer, Rounds = rounds, Salt = salt };
    }

    public static HashedPassword SAPPasswordAlgorithmAvoidToArray(string clearText, byte[] salt, HashAlgorithm hasher, int rounds = 1000)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(clearText);

        var initialArray = new byte[passwordBytes.Length + salt.Length];
        passwordBytes.CopyTo(initialArray, 0);
        salt.CopyTo(initialArray, passwordBytes.Length);
        
        var buffer = hasher.ComputeHash(initialArray);

        var roundBuffer = new byte[passwordBytes.Length + buffer.Length];
        passwordBytes.CopyTo(roundBuffer, 0);
        for (var i = 1; i < rounds; i++)
        {
            buffer.CopyTo(roundBuffer, passwordBytes.Length);
            buffer = hasher.ComputeHash(roundBuffer);
        }

        return new() { PasswordHash = buffer, Rounds = rounds, Salt = salt };
    }

    public static HashedPassword SAPPasswordAlgorithmArrayPooling(string clearText, byte[] salt, HashAlgorithm hasher, int rounds = 1000)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(clearText);

        var initialArraySize = passwordBytes.Length + salt.Length;
        var initialArray = Malloc(initialArraySize);
        passwordBytes.CopyTo(initialArray, 0);
        salt.CopyTo(initialArray, passwordBytes.Length);
        
        var buffer = hasher.ComputeHash(initialArray,0, initialArraySize);
        
        var roundBufferSize = passwordBytes.Length + buffer.Length;
        var roundBuffer = Malloc(roundBufferSize);
        passwordBytes.CopyTo(roundBuffer, 0);
        for (var i = 1; i < rounds; i++)
        {
            buffer.CopyTo(roundBuffer, passwordBytes.Length);
            buffer = hasher.ComputeHash(roundBuffer, 0, roundBufferSize);
        }
        var result = new HashedPassword() { PasswordHash = buffer, Rounds = rounds, Salt = salt };
        
        Free(roundBuffer);
        Free(initialArray);

        return result;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static byte[] Malloc(int size) => ArrayPool<byte>.Shared.Rent(size);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static void Free(in byte[] buffer) => ArrayPool<byte>.Shared.Return(buffer);
    }

    public static HashedPassword SAPPasswordAlgorithmReuseHashBuffers(string clearText, byte[] salt, HashAlgorithm hasher, int rounds = 1000)
    {
        var passwordByteLen = Encoding.UTF8.GetByteCount(clearText);
        using var passwordByteArray = RentedMemoryHandle.Malloc(passwordByteLen);
        var passwordBytes = passwordByteArray.AsSpan();
        
        Encoding.UTF8.GetBytes(clearText, passwordBytes);
        
        var hashSize = GetHashSize(hasher);
        
        // get our input array
        var hasherInputSize = passwordBytes.Length + Math.Max(salt.Length, hashSize);
        using var hashInputByteArray = RentedMemoryHandle.Malloc(hasherInputSize);
        var hashInput = hashInputByteArray.AsSpan();
        
        // prep the input array
        passwordBytes.CopyTo(hashInput);
        salt.CopyTo(hashInput[passwordBytes.Length..]);

        using var hashBytesArray = RentedMemoryHandle.Malloc(hashSize);
        var hashBytes = hashBytesArray.AsSpan();
        
        var initialSize = passwordBytes.Length + salt.Length;
        hasher.TryComputeHash(hashInput[..initialSize], hashBytes, out var _);

        var roundSize = passwordBytes.Length + hashSize;
        passwordBytes.CopyTo(hashInput);
        for (var i = 1; i < rounds; i++)
        {
            hashBytes[..hashSize].CopyTo(hashInput[passwordBytes.Length..]);
            hasher.TryComputeHash(hashInput[..roundSize], hashBytes, out var _);
        }
        
        return new() { PasswordHash = hashBytes[..hashSize].ToArray(), Rounds = rounds, Salt = salt };
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static int GetHashSize<T>(in T alg)
            => alg switch
            {
                SHA1 => SHA1.HashSizeInBytes,
                SHA256 => SHA256.HashSizeInBytes,
                SHA384 => SHA384.HashSizeInBytes,
                SHA512 => SHA512.HashSizeInBytes,
                _ => throw new NotImplementedException(),
            };
    }

    internal struct RentedMemoryHandle : IDisposable
    {
        private readonly byte[] _buffer;
        private int _size;

        public Span<byte> AsSpan() => _buffer.AsSpan()[.._size];

        private RentedMemoryHandle(int size)
        {
            _buffer = ArrayPool<byte>.Shared.Rent(size);
            _size = size;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static RentedMemoryHandle Malloc(int size) => new(size);

        public void Dispose()
        {
            ArrayPool<byte>.Shared.Return(_buffer);
        }
    }

    public static HashedPassword SAPPasswordAlgorithmStackAllocation(string clearText, byte[] salt, HashAlgorithm hasher, int rounds = 1000)
    {
        var passwordBytesCount = Encoding.UTF8.GetByteCount(clearText);
        Span<byte> passwordBytes = stackalloc byte[passwordBytesCount];
        Encoding.UTF8.GetBytes(clearText, passwordBytes);

        var hashSize = GetHashSize(hasher);

        // get our input array
        var hasherInputSize = passwordBytes.Length + Math.Max(salt.Length, hashSize);
        Span<byte> hashInput = stackalloc byte[hasherInputSize];

        // prep the input array
        passwordBytes.CopyTo(hashInput);
        salt.CopyTo(hashInput[passwordBytes.Length..]);

        Span<byte> hashBytes = stackalloc byte[hashSize];
        var initialSize = passwordBytes.Length + salt.Length;

        hasher.TryComputeHash(hashInput[..initialSize], hashBytes, out var _);

        var roundSize = passwordBytes.Length + hashSize;
        passwordBytes.CopyTo(hashInput);
        for (var i = 1; i < rounds; i++)
        {
            hashBytes.CopyTo(hashInput[passwordBytes.Length..]);
            hasher.TryComputeHash(hashInput[..roundSize], hashBytes, out var _);
        }

        return new HashedPassword() { PasswordHash = hashBytes.ToArray(), Rounds = rounds, Salt = salt };
    }

    public static HashedPassword SAPPasswordAlgorithmStackAllocationUnroll(string clearText, byte[] salt, HashAlgorithm hasher, int rounds = 1000)
    {
        var passwordBytesCount = Encoding.UTF8.GetByteCount(clearText);
        Span<byte> passwordBytes = stackalloc byte[passwordBytesCount];
        Encoding.UTF8.GetBytes(clearText, passwordBytes);

        var hashSize = GetHashSize(hasher);

        // get our input array
        var hasherInputSize = passwordBytes.Length + Math.Max(salt.Length, hashSize);
        Span<byte> hashInput = stackalloc byte[hasherInputSize];

        // prep the input array
        passwordBytes.CopyTo(hashInput);
        salt.CopyTo(hashInput[passwordBytes.Length..]);

        Span<byte> hashBytes = stackalloc byte[hashSize];
        var initialSize = passwordBytes.Length + salt.Length;

        hasher.TryComputeHash(hashInput[..initialSize], hashBytes, out var _);

        var roundSize = passwordBytes.Length + hashSize;
        passwordBytes.CopyTo(hashInput);
        
        var left = rounds - 1;
        const int unroll = 6;
        var loops = left / unroll;
        var additional = left - loops * unroll;

        for (var i = 0; i < loops; i++)
        {
            hashBytes.CopyTo(hashInput[passwordBytes.Length..]);
            hasher.TryComputeHash(hashInput[..roundSize], hashBytes, out var _);
            hashBytes.CopyTo(hashInput[passwordBytes.Length..]);
            hasher.TryComputeHash(hashInput[..roundSize], hashBytes, out var _);
            hashBytes.CopyTo(hashInput[passwordBytes.Length..]);
            hasher.TryComputeHash(hashInput[..roundSize], hashBytes, out var _);
            hashBytes.CopyTo(hashInput[passwordBytes.Length..]);
            hasher.TryComputeHash(hashInput[..roundSize], hashBytes, out var _);
            hashBytes.CopyTo(hashInput[passwordBytes.Length..]);
            hasher.TryComputeHash(hashInput[..roundSize], hashBytes, out var _);
            hashBytes.CopyTo(hashInput[passwordBytes.Length..]);
            hasher.TryComputeHash(hashInput[..roundSize], hashBytes, out var _);
        }

        for (var i = 0; i < additional; i++)
        {
            hashBytes.CopyTo(hashInput[passwordBytes.Length..]);
            hasher.TryComputeHash(hashInput[..roundSize], hashBytes, out var _);
        }

        return new HashedPassword() { PasswordHash = hashBytes.ToArray(), Rounds = rounds, Salt = salt };
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static int GetHashSize<T>(in T alg) where T: HashAlgorithm
        => alg switch
        {
            SHA1 => SHA1.HashSizeInBytes,
            SHA256 => SHA256.HashSizeInBytes,
            SHA384 => SHA384.HashSizeInBytes,
            SHA512 => SHA512.HashSizeInBytes,
            _ => throw new NotImplementedException(),
        };
}