using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace hsm_client_dotnet
{
    class Output : IOutput
    {
        public void Write(IntPtr buffer, ref UInt32 size)
        {
            int o = data.Length;
            Array.Resize<byte>(ref data, o + (int) size);
            Marshal.Copy(buffer, data, o, (int) size);
        }

        public byte[] data = new byte[0];
    }
}
