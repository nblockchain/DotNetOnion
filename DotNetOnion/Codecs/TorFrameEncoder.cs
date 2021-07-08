using DotNetOnion.Helpers;
using DotNetty.Buffers;
using DotNetty.Codecs;
using DotNetty.Transport.Channels;
using NOnion.Cells;
using System;
using System.Collections.Generic;
using System.Text;

namespace DotNetOnion.Codecs
{
    public class TorFrameEncoder : MessageToByteEncoder<TorFrame>
    {
        protected override void Encode(IChannelHandlerContext context, TorFrame message, IByteBuffer output)
        {
            output.WriteUnsignedShort(message.CircuitId);
            output.WriteByte(message.Command);

            if (Command.IsVariableLength(message.Command))
                output.WriteUnsignedShort((ushort)message.Payload.Length);

            output.WriteBytes(message.Payload);
        }
    }
}
