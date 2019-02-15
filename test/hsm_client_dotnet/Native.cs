using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace hsm_client_dotnet
{
    class Native
    {
        [DllImport("libhsm_client.dll",
            EntryPoint = "CreateCryptoContext", CallingConvention = CallingConvention.Cdecl)]
        protected static extern IntPtr CreateCryptoContextNative(short keyId,
            [MarshalAs(UnmanagedType.LPStr)]string ip, short port, IError errSink);

        [DllImport("libhsm_client.dll",
            EntryPoint = "CreateCipher", CallingConvention = CallingConvention.Cdecl)]
        protected static extern IntPtr CreateCipherNative(ICryptoContext context, IError errSink);

        [DllImport("libhsm_client.dll",
            EntryPoint = "CreateRsaCipher", CallingConvention = CallingConvention.Cdecl)]
        protected static extern IntPtr CreateRsaCipherNative(ICryptoContext context, IError errSink);

        /// <summary>
        /// Create crypto context object
        /// </summary>
        /// <param name="keyId">Key identifier from server configuration file</param>
        /// <param name="ip">Ip address of the server</param>
        /// <param name="port">Port that server is listenning for incomming connection (8001) </param>
        /// <param name="errSink">Error handler. May be null</param>
        /// <returns>ICryptoContext object that represent crypto context</returns>
        public static ICryptoContext CreateCryptoContext(short keyId, string ip, short port, IError errSink)
        {
            IntPtr ret = CreateCryptoContextNative(keyId, ip, port, errSink);
            if (ret == IntPtr.Zero)
                return null;
            return Marshal.GetObjectForIUnknown(ret) as ICryptoContext;
        }

        /// <summary>
        /// Create cipher for specified crypto context. It creates any cipher object (Rsa, Symmetric cipher, GOST).
        /// </summary>
        /// <param name="context">Crypto context</param>
        /// <param name="errSink">Error handler. May be null</param>
        /// <returns>ICipher object that represent cipher</returns>
        public static ICipher CreateCipher(ICryptoContext context, IError errSink)
        {
            IntPtr ret = CreateCipherNative(context, errSink);
            if (ret == IntPtr.Zero)
                return null;
            return Marshal.GetObjectForIUnknown(ret) as ICipher;
        }

        /// <summary>
        /// Create Rsa cipher for specified crypto context. It creates any cipher object (Rsa, Symmetric cipher, GOST), 
        /// but provides extended interface to apply trapdoor permutation.
        /// </summary>
        /// <param name="context">Crypto context</param>
        /// <param name="errSink">Error handler. May be null</param>
        /// <returns>IRsaCipher object that represent cipher</returns>
        public static IRsaCipher CreateRsaCipher(ICryptoContext context, IError errSink)
        {
            IntPtr ret = CreateRsaCipherNative(context, errSink);
            if (ret == IntPtr.Zero)
                return null;
            return Marshal.GetObjectForIUnknown(ret) as IRsaCipher;
        }
    }
}
