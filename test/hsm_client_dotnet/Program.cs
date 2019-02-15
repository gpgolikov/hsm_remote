using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace hsm_client_dotnet
{
    class Program
    {
        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        static void Main(string[] args)
        {
            Error errorSink = new Error();
            ICryptoContext context = Native.CreateCryptoContext(Convert.ToInt16(args[3]), args[2], 8001, errorSink);
            if (errorSink.code != ErrorCode.Success)
            {
                Console.Error.WriteLine("CreateCryptoContext error: " + errorSink.message);
                return;
            }

            Console.WriteLine("Crypto context created");

            IRsaCipher cipher = Native.CreateRsaCipher(context, errorSink);
            if (errorSink.code != ErrorCode.Success)
            {
                Console.Error.WriteLine("CreateRsaCipher error: " + errorSink.message);
                return;
            }

            Console.WriteLine("Rsa cipher created");

            string[] input_hexs = System.IO.File.ReadAllLines(args[0]);
            string[] output_hexs = new string[input_hexs.Length];

            for (int i = 0; i < input_hexs.Length; ++i)
            {
                var input_hex = input_hexs[i];
                if (input_hex.Length == 0)
                    continue;

                Console.WriteLine("Permutation start...");

                Input input = new Input();
                Output output = new Output();

                input.data = StringToByteArray(input_hex);

                cipher.TrapdoorPri(input, output, errorSink);
                if (errorSink.code != ErrorCode.Success)
                {
                    Console.Error.WriteLine("TrapdoorPri error: " + errorSink.message);
                    return;
                }

                Console.WriteLine("Permutation completed");
                output_hexs[i] = ByteArrayToString(output.data);
            }

            System.IO.File.WriteAllLines(args[1], output_hexs);
        }
    }
}
