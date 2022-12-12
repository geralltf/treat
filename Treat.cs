using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Microsoft.Win32;

namespace Treat.Forensics
{
    public class FileSystemStructure
    {
        public const long depthReached = 2;
        public const long structLimit = -1;
        public const bool start = false;
        internal enum Type
        {
            Partial,
            Complete
        }
        internal enum AlgorithmType
        {
            DFS,
            BFS
        }
        public static void Analyse()
        {
            Console.BufferHeight = short.MaxValue-1;
            Analyse("C:\\", 1, true, true, false);
        }
        private static float Analyse(string path, long curDepth, bool isRoot, bool printing, bool bail, AlgorithmType type = AlgorithmType.BFS)
        {
            long id = 0;
            float totalTotalLen = 0;
            float totalDepth = 0;
            Data<Directory> data = new Data<Directory>(type);
            data.Add(new Directory { Level = curDepth, Path = path, Name = (new System.IO.DirectoryInfo(path)).Name, Root = (new System.IO.DirectoryInfo(path)).Parent.FullName });

            long sz = 1024;
            long[] n = new long[sz];
            Random random = new Random(0);
            for (long i=0;i<sz;i++)
            {
                n[i] = random.NextInt64(long.MaxValue);
            }

            while (data.Count <= structLimit ^ data.Count > 0)
            {
                Directory node = data.RemoveTop();
                if (node != null)
                {
                    if (printing) Console.WriteLine(node.Name);
                    if (((curDepth < depthReached) || start) && !(node.Name.StartsWith(".")))
                    {
                        string s = string.Empty;
                        if (printing && !bail)
                            s = s + ("└───(" + ((node.Path.Last() == '\\') ? node.Path.Substring(0, node.Path.Length - 1) : node.Path)) + "\n";
                        IEnumerable<string> dirs = System.IO.Directory.EnumerateDirectories(node.Path);
                        float totalLen = 0;
                        foreach (string dir in dirs)
                        {
                            id = id + 1;
                            Directory sub = new Directory { Id = id, Level = curDepth + 1, Path = dir, Name = (new System.IO.DirectoryInfo(dir)).Name, Root = (new System.IO.DirectoryInfo(dir)).Parent.FullName };
                            data.Add(sub);
                            totalDepth++;
                            if (printing) for (long i = 0; i < curDepth; i++) s = s + "\t";
                            if (printing) s = s + sub.Name + "\n";
                            if (!sub.Name.StartsWith("."))
                            {
                                totalLen = 0;
                                try
                                {
                                    var files = System.IO.Directory.GetFiles(dir);
                                    long count = files.Length;
                                    foreach (var fi in files)
                                    {
                                        id = id + 1;
                                        System.IO.FileInfo file = new System.IO.FileInfo(fi);
                                        long len = file.Length;
                                        File dataStore = new File { Id = id, Level = curDepth, Name = file.Name, Path = file.FullName, Root = file.Directory.FullName };
                                        if (printing) for (long i = 0; i < curDepth; i++) s = s + "\t";
                                        if (printing) s = s + ("├───" + file.Name + " " + len);
                                        totalLen = totalLen + len;
                                        if (printing) s = s + (" " + totalLen);

                                        long state = 0;
                                        long a = (((long)(totalLen * totalLen)) << 3 >> 13 << 6);
                                        long b = (((long)totalLen) ^ (long)(totalLen) >> 6 << 14 >> 16);
                                        state = (a ^ b) ^ n[id % sz];
                                        float st = (float)(state * 0.000000000000001f);

                                        float left = 0.00014f;
                                        float right = (totalLen + st) + MathF.Sin(0.14f * count);
                                        float middle = (totalTotalLen + st) + MathF.Sin(0.14f * count);

                                        float totalLenB = MathF.Pow(left, right) + (st * 0.00000000001f);
                                        float seq = MathF.Pow(left, middle) + (st) * ((len << 12));

                                        totalTotalLen += totalLenB;
                                        if (printing) s = s + (" " + totalTotalLen + " " + seq) + "\n";
                                    }
                                }
                                catch (Exception ex)
                                {

                                }
                            }
                        }

                        totalLen = 0;
                        try
                        {
                            var files = System.IO.Directory.GetFiles(path);
                            long count = files.Length;
                            foreach (var fi in files)
                            {
                                id = id + 1;
                                System.IO.FileInfo file = new System.IO.FileInfo(fi);
                                long len = file.Length;
                                File dataStore = new File { Id = id, Level = curDepth, Name = file.Name, Path = file.FullName, Root = file.Directory.FullName };
                                if (printing) for (long i = 0; i < curDepth; i++) s = s + "\t";
                                if (printing) s = s + ("├───" + file.Name + " " + len);

                                totalLen = totalLen + len;
                                if (printing) s = s + (" " + totalLen);
                                long state = 0;
                                long a = (((long)(totalLen * totalLen)) << 3 >> 13 << 6);
                                long b = (((long)totalLen) ^ (long)(totalLen) >> 6 << 14 >> 16);
                                state = (a ^ b) ^ n[id % sz];
                                float st = (float)(state * 0.000000000000001f);

                                float left = 0.00014f;
                                float right = (totalLen + st) + MathF.Sin(0.14f * count);
                                float middle = (totalTotalLen + st) + MathF.Sin(0.14f * count);

                                float totalLenB = MathF.Pow(left, right) + (st * 0.00000000001f);
                                float seq = MathF.Pow(left, middle) + (st) * ((len << 12));
                                
                                totalTotalLen += totalLenB;
                                if (printing) s = s + (" " + totalTotalLen + " " + seq) + "\n";
                            }
                        }
                        catch (Exception ex)
                        {

                        }
                        //if (printing && !bail) s = s.Replace("└───(" + ((path.Last() == '\\') ? path.Substring(0, path.Length - 1) : path), "└───ROOT(" + ((path.Last() == '\\') ? path.Substring(0, path.Length - 1) : path) + " " + totalTotalLen);
                        if (printing) for (long i = 0; i < curDepth - 1; i++) s = "\t" + s;
                        if (printing) for (long i = 0; i < curDepth - 1; i++) s = s + "\t";
                        if (printing) s = s + " " + totalTotalLen + " bytes\n";
                        if (printing && !bail) Console.WriteLine(s);
                    }
                }
            }
            Console.WriteLine("Total depth reached: " + totalDepth);
            return totalTotalLen;
        }
        private long R(ref long state)
        {
            long value = state;
            value <<= 4;
            value >>= 9;
            value <<= 12;
            value ^= 0x387216304E;
            value = H(value, value);
            state = value;
            return value;
        }
        private long H(long left, long right)
        {
            long y = 0;
            for (long i = 0; i < 64; i++)
            {
                y = (left >> 0x03) ^ (right >> 0x02);
                y <<= 4;
                y >>= 9;
                y <<= 12;
                y ^= 0x387216304E;
            }
            return y;
        }

        public byte[] ID(byte[] i, long size)
        {
            long s = 0xA0FCD12B3987239;
            long iv = 0x23012963857AFDB8;
            long r  = R(ref s);
            long state = iv ^ r;
            long a = R(ref s);
            long b = R(ref s);
            long c = R(ref s);
            long d = R(ref s);
            for (long perm=0;perm<64;perm++)
            {
                iv <<= 3;
                iv >>= 8;
                state = iv ^ (state << 1) | (iv & 1);
            }
            for (long A = 0; A < size; A++)
            {
                long v = i[A];
                a = a ^ v;
                b = b ^ v;
                c = c ^ v;
                d = d ^ v;
            }
            byte[] ret = new byte[16 * 4];
            ret[0] = BitConverter.GetBytes(a)[sizeof(long) * 0];
            ret[1] = BitConverter.GetBytes(a)[sizeof(long) * 1];
            ret[2] = BitConverter.GetBytes(a)[sizeof(long) * 2];
            ret[3] = BitConverter.GetBytes(a)[sizeof(long) * 3];
            ret[4] = BitConverter.GetBytes(b)[sizeof(long) * 0];
            ret[5] = BitConverter.GetBytes(b)[sizeof(long) * 1];
            ret[6] = BitConverter.GetBytes(b)[sizeof(long) * 2];
            ret[7] = BitConverter.GetBytes(b)[sizeof(long) * 3];
            ret[8] = BitConverter.GetBytes(c)[sizeof(long) * 0];
            ret[9] = BitConverter.GetBytes(c)[sizeof(long) * 1];
            ret[10] = BitConverter.GetBytes(c)[sizeof(long) * 2];
            ret[11] = BitConverter.GetBytes(c)[sizeof(long) * 3];
            ret[12] = BitConverter.GetBytes(d)[sizeof(long) * 0];
            ret[13] = BitConverter.GetBytes(d)[sizeof(long) * 1];
            ret[14] = BitConverter.GetBytes(d)[sizeof(long) * 2];
            ret[15] = BitConverter.GetBytes(d)[sizeof(long) * 3];
            return ret;
        }
        private File CreateFileNode(string name, string path, string root)
        {
            return new File { Name = name, Path = path, Root = root };
        }
        private Directory CreateDirNode(string name, string path, string root)
        {
            return new Directory { Name = name, Path = path, Root = root };
        }
    }

    public class Data<T>
    {
        public long Count { get; set; }
        private Stack<T> a;
        private Queue<T> b;
        internal FileSystemStructure.AlgorithmType AlgorithmType { get; set; }
        internal Data(FileSystemStructure.AlgorithmType algorithmType)
        {
            a = new Stack<T>();
            b = new Queue<T>();
            Count = 0;
            AlgorithmType = algorithmType;
        }

        public void Add(T data)
        {
            Count = Count + 1;
            if (AlgorithmType == FileSystemStructure.AlgorithmType.BFS)
            {
                b.Enqueue(data);
            }
            if (AlgorithmType == FileSystemStructure.AlgorithmType.DFS)
            {
                a.Push(data);
            }
        }
        public T RemoveTop()
        {
            Count = Count - 1;
            T? data = default(T);
            if (AlgorithmType == FileSystemStructure.AlgorithmType.BFS)
            {
                data = b.Dequeue();
            }
            if (AlgorithmType == FileSystemStructure.AlgorithmType.DFS)
            {
                data = a.Pop();
            }
            return data;
        }
    }
    public class File : Node
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public string Root { get; set; }
    }
    public class Directory : Node
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public string Root { get; set; }
    }
    public abstract class Node
    {
        public long Id { get; set; }
        public long Level { get; set; }
    }
}
