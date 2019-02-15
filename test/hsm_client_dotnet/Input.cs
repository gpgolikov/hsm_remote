using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace hsm_client_dotnet
{
    class Input : IInput
    {
        public void Read(IntPtr buffer, ref UInt32 size, ref bool more_avail)
        {
            if (data.Length == 0)
            {
                size = 0;
                more_avail = false;
                return;
            }

            byte[] ret = data.Take((int) size).ToArray();
            Marshal.Copy(ret, 0, buffer, ret.Length);

            data = data.Skip((int) size).ToArray();
            size = (UInt32) ret.Length;
            more_avail = data.Length > 0;
        }

        public byte[] data;
    }
}
