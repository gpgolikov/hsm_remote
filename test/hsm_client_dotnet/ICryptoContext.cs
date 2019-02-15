using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace hsm_client_dotnet
{
    /// <summary>
    /// Crypto context object interface
    /// </summary>
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown),
        Guid("825346CA-FE0C-4469-9C56-B355547FA885")]
    interface ICryptoContext
    {
    }
}
