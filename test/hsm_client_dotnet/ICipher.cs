using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace hsm_client_dotnet
{
    /// <summary>
    /// Cipher object interface
    /// </summary>
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown),
        Guid("2465d915-d66a-497d-b90e-c2aec2fb774b")]
    interface ICipher
    {
        /// <summary>
        /// Decrypt data from input stream and transfer decrypted data to output stream
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="errorSink">Error handler. May be null</param>
        void Decrypt(IInput input, IOutput output, IError errorSink);

        /// <summary>
        /// Encrypt data from input stream and transfer encrypted data to output stream
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="errorSink">Error handler. May be null</param>
        void Encrypt(IInput input, IOutput output, IError errorSink);
    }
}
