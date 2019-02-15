using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace hsm_client_dotnet
{
    /// <summary>
    /// Output stream
    /// </summary>
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown),
        Guid("0d3823ff-cbd4-4c76-b382-d0f53189776f")]
    interface IOutput
    {
        /// <summary>
        /// Callback for writting data
        /// </summary>
        /// <param name="data">Source data buffer</param>
        /// <param name="size">Data size in source buffer. After execution contains real transferred data size</param>
        void Write(IntPtr data, ref UInt32 size);
    }
}
