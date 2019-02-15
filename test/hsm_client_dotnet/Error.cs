using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace hsm_client_dotnet
{
    class Error : IError
    {
        public void SetError(ErrorCode code, [MarshalAs(UnmanagedType.LPWStr)] string message)
        {
            this.code = code;
            this.message = message;
            lastError = 0;
        }

        public void SetError(ErrorCode code, [MarshalAs(UnmanagedType.LPWStr)] string message, ushort lastError)
        {
            this.code = code;
            this.message = message;
            this.lastError = lastError;
        }

        public ErrorCode code;
        public string message;
        public ushort lastError;
    }
}
