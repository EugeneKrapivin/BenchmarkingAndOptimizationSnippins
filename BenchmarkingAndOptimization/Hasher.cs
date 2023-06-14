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
}