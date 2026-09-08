namespace Teste.Native;

public sealed record Signature(string Kind, int? Mode, string Extractor, int HeaderBytes, bool WholeFile);

public static class Magic
{
    private static readonly (int Off, byte[] Head, Signature Sig)[] Table =
    {
        (0, new byte[]{ 0x37,0x7A,0xBC,0xAF,0x27,0x1C },
            new("7z", 11000, "7z2john.pl", 65536, false)),
        (0, new byte[]{ 0x52,0x61,0x72,0x21,0x1A,0x07,0x01 },
            new("rar5", 13000, "rar2john", 65536, false)),
        (0, new byte[]{ 0x52,0x61,0x72,0x21,0x1A,0x07,0x00 },
            new("rar3-hp", 12500, "rar2john", 65536, false)),
        (0, new byte[]{ 0x50,0x4B,0x03,0x04 },
            new("zip", 17200, "zip2john (AES v2 -> 22100)", 0, false)),
        (0, new byte[]{ 0x3C,0xB4,0xFF,0x5F },
            new("keepass", 13400, "keepass2john", 0, false)),
        (0, new byte[]{ 0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1 },
            new("ole-office", null, "office2john.py -> 24100 agile / 21100-21300 legacy", 0, false)),
        (0, new byte[]{ 0x25,0x50,0x44,0x46,0x2D },
            new("pdf", 10500, "pdf2john.pl", 0, false)),
        (0, new byte[]{ 0x62,0x31,0x06,0x00 },
            new("bdb-wallet", 11300, "extract_bitcoin_fast.py", 0, false)),
        (0, new byte[]{ 0x4B,0x44,0x4D,0x56 },
            new("vmdk", null, "montar e re-triar", 0, true)),
        (8, new byte[]{ 0x76,0x68,0x64,0x78 },
            new("vhdx", null, "montar e re-triar", 0, true)),
    };

    private static readonly Dictionary<string, Signature> ByExt = new(StringComparer.OrdinalIgnoreCase)
    {
        [".7z"]        = new("7z", 11000, "7z2john.pl", 65536, false),
        [".rar"]       = new("rar5", 13000, "rar2john", 65536, false),
        [".zip"]       = new("zip", 17200, "zip2john", 0, false),
        [".kdbx"]      = new("keepass2", 13400, "keepass2john", 0, false),
        [".kdb"]       = new("keepass1", 13400, "keepass2john", 0, false),
        [".gpg"]       = new("gpg", 19600, "gpg2john", 0, false),
        [".pgp"]       = new("gpg", 19600, "gpg2john", 0, false),
        [".hc"]        = new("veracrypt", null, "vcswarm.sh -> 13751/13752/13753", 65536, false),
        [".tc"]        = new("truecrypt", null, "vcswarm.sh -> 13500/13600", 65536, false),
        [".veracrypt"] = new("veracrypt", null, "vcswarm.sh -> 13751/13752/13753", 65536, false),
        [".img"]       = new("imagem-disco", null, "dislocker/montar e re-triar", 0, true),
        [".vhd"]       = new("vhd", null, "montar e re-triar", 0, true),
        [".vmdk"]      = new("vmdk", null, "montar e re-triar", 0, true),
        [".vhdx"]      = new("vhdx", null, "montar e re-triar", 0, true),
        [".bak"]       = new("mssql-backup", null, "mssql2john -> 17300", 0, true),
        [".pst"]       = new("pst", null, "criptografia e por-propriedade: verificar msgclass", 0, true),
        [".opVault"]   = new("1password", null, "extrair vault opfs", 0, true),
    };

    public static Signature? Classify(string path, ReadOnlySpan<byte> head)
    {
        foreach (var (off, pat, sig) in Table)
            if (head.Length >= off + pat.Length && head.Slice(off, pat.Length).SequenceEqual(pat))
                return sig;

        if (head.Length > 16 && System.Text.Encoding.ASCII.GetString(head[..16]).Contains("-----BEGIN PGP"))
            return new("gpg", 19600, "gpg2john", 0, false);

        var sqlitePlain = head.Length >= 16 &&
                          System.Text.Encoding.ASCII.GetString(head[..16]) == "SQLite format 3\0";
        if (!sqlitePlain && (path.EndsWith(".db", StringComparison.OrdinalIgnoreCase)
                          || path.EndsWith(".sqlite", StringComparison.OrdinalIgnoreCase)
                          || path.EndsWith(".sqlite3", StringComparison.OrdinalIgnoreCase)))
            return new("sqlcipher", null, "sqlcipher_brute.py", 4096, false);

        return ByExt.GetValueOrDefault(Path.GetExtension(path));
    }

    public static bool ZipEncrypted(ReadOnlySpan<byte> head) =>
        head.Length > 10 && (head[6] & 0x01) == 0x01;   // general purpose bit 0

    public static bool PdfEncrypted(byte[] headOrTail) =>
        System.Text.Encoding.ASCII.GetString(headOrTail).Contains("/Encrypt");

    public static bool OLEEncrypted(byte[] headOrWhole) =>
        System.Text.Encoding.Unicode.GetString(headOrWhole).Contains("EncryptedPackage")
        || System.Text.Encoding.Unicode.GetString(headOrWhole).Contains("_VBA_PROJECT_CUR");
}