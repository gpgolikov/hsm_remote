using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace hsm_client_dotnet
{
    /// <summary>
    /// Input stream interface
    /// </summary>
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown),
        Guid("9036c524-1e9c-47e2-9601-899f2251ea5b")]
    interface IInput
    {
        /// <summary>
        /// Callback for reading input data
        /// </summary>
        /// <param name="buffer">Destination data buffer</param>
        /// <param name="size">Required data size. After execution contains real transferred data size</param>
        /// <param name="more_avail">More data available for reading indicator</param>
        void Read(IntPtr buffer, ref UInt32 size, ref bool more_avail);
    }
}
