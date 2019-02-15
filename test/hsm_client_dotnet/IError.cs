using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace hsm_client_dotnet
{
    enum ErrorCode : int
    {
        Success = 0,
        IncorrectArgument,
        CryptoError, // has additional information
        InternalError,
        RemoteError
    }

    /// <summary>
    /// Error handler interface
    /// </summary>
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown),
        Guid("B8233CB8-7319-48E1-AC7E-0EAD0973FFE3")]
    interface IError
    {
        /// <summary>
        /// Callback for recieving error information
        /// </summary>
        /// <param name="code">Error code</param>
        /// <param name="message">Error message</param>
        void SetError(ErrorCode code, [MarshalAs(UnmanagedType.LPWStr)]string message);

        /// <summary>
        /// Callback for recieving error information
        /// </summary>
        /// <param name="code">Error code</param>
        /// <param name="message">Error message</param>
        /// <param name="lastError">GetLastError() returned value</param>
        void SetError(ErrorCode code, [MarshalAs(UnmanagedType.LPWStr)]string message, ushort lastError);
    }
}
