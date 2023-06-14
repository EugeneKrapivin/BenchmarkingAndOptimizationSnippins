using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace BenchmarkingAndOptimization;

public record struct HashedPassword(byte[] PasswordHash, byte[] Salt, int Rounds);

public class Hasher
{ 
    // SAP ABAP password hashing algorithm gist
    // get clear text password utf8 bytes
    // r_1 = sha(salt.password)
    // r_n = sha(r_n-1.password)

    public HashedPassword SAPPasswordAlgorithmNaive(string clearText, byte[] salt, HashAlgorithm hasher, int rounds = 1000)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(clearText);

        var buffer = hasher.ComputeHash(passwordBytes.Concat(salt).ToArray());

        for (var i = 1; i < rounds; i++)
        {
            buffer = hasher.ComputeHash(passwordBytes.Concat(buffer).ToArray());
        }

        return new() { PasswordHash = buffer, Rounds = rounds, Salt = salt };
    }

    public HashedPassword SAPPasswordAlgorithmAvoidToArray(string clearText, byte[] salt, HashAlgorithm hasher, int rounds = 1000)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(clearText);

        var initialArray = new byte[passwordBytes.Length + salt.Length];
        passwordBytes.CopyTo(initialArray, 0);
        salt.CopyTo(initialArray, passwordBytes.Length);
        var buffer = hasher.ComputeHash(initialArray);

        var roundBuffer = new byte[passwordBytes.Length + buffer.Length];
        for (var i = 1; i < rounds; i++)
        {
            passwordBytes.CopyTo(roundBuffer, 0);
            buffer.CopyTo(roundBuffer, passwordBytes.Length);
            buffer = hasher.ComputeHash(roundBuffer);
        }

        return new() { PasswordHash = buffer, Rounds = rounds, Salt = salt };
    }

    public HashedPassword SAPPasswordAlgorithmArrayPooling(string clearText, byte[] salt, HashAlgorithm hasher, int rounds = 1000)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(clearText);

        var initialArraySize = passwordBytes.Length + salt.Length;
        var initialArray = ArrayPool<byte>.Shared.Rent(initialArraySize);
        passwordBytes.CopyTo(initialArray, 0);
        salt.CopyTo(initialArray, passwordBytes.Length);
        
        var buffer = hasher.ComputeHash(initialArray,0, initialArraySize);
        ArrayPool<byte>.Shared.Return(initialArray);

        var roundBufferSize = passwordBytes.Length + buffer.Length;
        var roundBuffer = ArrayPool<byte>.Shared.Rent(roundBufferSize);
        for (var i = 1; i < rounds; i++)
        {
            passwordBytes.CopyTo(roundBuffer, 0);
            buffer.CopyTo(roundBuffer, passwordBytes.Length);
            buffer = hasher.ComputeHash(roundBuffer, 0, roundBufferSize);
        }
        var result = new HashedPassword() { PasswordHash = buffer, Rounds = rounds, Salt = salt };
        
        return result;
    }

    public HashedPassword SAPPasswordAlgorithmReuseHashBuffers(string clearText, byte[] salt, HashAlgorithm hasher, int rounds = 1000)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(clearText);
        var hashSize = GetHashSize(hasher);
        // get our input array
        var hasherInputSize = passwordBytes.Length + Math.Max(salt.Length, hashSize);
        var hashInputArray = Rent(hasherInputSize);
        var hashInput = hashInputArray.AsSpan();
        
        // prep the input array
        passwordBytes.CopyTo(hashInput);
        salt.CopyTo(hashInput[passwordBytes.Length..]);

        var hashBytesArray = Rent(hashSize);
        var hashBytes = hashBytesArray.AsSpan();
        var initialSize = passwordBytes.Length + salt.Length;
        Hash(hasher, hashInput[..initialSize], hashBytes);

        var roundSize = passwordBytes.Length + hashSize;
        for (var i = 1; i < rounds; i++)
        {
            passwordBytes.CopyTo(hashInput);
            hashBytes[..hashSize].CopyTo(hashInput[passwordBytes.Length..]);
            Hash(hasher, hashInput[..roundSize], hashBytes);
        }
        var passwordHash = new byte[hashSize];
        hashBytes[..hashSize].CopyTo(passwordHash);
        var result = new HashedPassword() { PasswordHash = passwordHash, Rounds = rounds, Salt = salt };
        Free(hashInputArray);
        Free(hashBytesArray);

        return result;

        static int Hash<T>(T alg, Span<byte> hasherInput, Span<byte> hashBytes)
            => alg switch
            {
                SHA1 => SHA1.HashData(hasherInput, hashBytes),
                SHA256 => SHA256.HashData(hasherInput, hashBytes),
                SHA384 => SHA384.HashData(hasherInput, hashBytes),
                SHA512 => SHA512.HashData(hasherInput, hashBytes),
                _ => throw new NotImplementedException(),
            };
        static int GetHashSize<T>(T alg)
        => alg switch
        {
            SHA1 => SHA1.HashSizeInBytes,
            SHA256 => SHA256.HashSizeInBytes,
            SHA384 => SHA384.HashSizeInBytes,
            SHA512 => SHA512.HashSizeInBytes,
            _ => throw new NotImplementedException(),
        };
        static byte[] Rent(int size) => ArrayPool<byte>.Shared.Rent(size);
        static void Free(byte[] buffer) => ArrayPool<byte>.Shared.Return(buffer);

    }
}