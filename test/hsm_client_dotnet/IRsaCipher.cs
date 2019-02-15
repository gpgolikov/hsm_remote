using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace hsm_client_dotnet
{
    /// <summary>
    /// Extended cipher object interface - let apply poor RSA permutation
    /// </summary>
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown),
        Guid("1a20e261-1b77-45de-a4f6-34625a5bcb67")]
    interface IRsaCipher // : ICipher - COM limitations of interface visibility
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

        /// <summary>
        /// Apply RSA permutation on public key on data from input stream and transfer new data to output stream
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="errorSink">Error handler. May be null</param>
        void TrapdoorPub(IInput input, IOutput output, IError errorSink);

        /// <summary>
        /// Apply RSA permutation on private key on data from input stream and transfer new data to output stream
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="errorSink">Error handler. May be null</param>
        void TrapdoorPri(IInput input, IOutput output, IError errorSink);
    }
}
