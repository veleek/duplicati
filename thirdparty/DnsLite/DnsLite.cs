//Dnslite.cs 
//From: http://www.csharphelp.com/2005/12/dns-client-utility/
/** 
    csc /target:library /out:DnsLib.dll /keyfile:..\..\Duplicati\GUI\Duplicati.snk DnsLite.cs 
*/ 
using System; 
using System.IO; 
using System.Text; 
using System.Net.Sockets; 
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DnsLib
{
    public class MXRecord
    {
        public int preference = -1;
        public string exchange = null;
        public override string ToString()
        {
            return "Preference : " + preference + " Exchange : " + exchange;
        }
    }

    public class DnsLite
    {
        private const int DNS_PORT = 53;
        private static readonly Encoding ASCII = Encoding.ASCII;

        private int id = DateTime.Now.Millisecond * 60;
        private byte[] data;
        private int position;
        private int length;
        private string name;
        
        private int getNewId()
        {
            //return a new id 
            return ++id;
        }

        public async Task<List<MXRecord>> getMXRecords(string host, string serverAddress)
        {
            //opening the UDP socket at DNS server 
            //use UDPClient, if you are still with Beta1 
            UdpClient dnsClient = new UdpClient(serverAddress, DNS_PORT);
            //preparing the DNS query packet. 
            byte[] query = makeQuery(getNewId(), host);
            //send the data packet 
            await dnsClient.SendAsync(query, query.Length);

            //receive the data packet from DNS server 
            var result = await dnsClient.ReceiveAsync();
            return makeResponse(result.Buffer);
        }

        //for packing the information to the format accepted by server 
        private byte[] makeQuery(int id, String name)
        {
            var query = new byte[512];
            for (int i = 0; i < 512; ++i)
            {
                query[i] = 0;
            }
            query[0] = (byte)(id >> 8);
            query[1] = (byte)(id & 0xFF);
            query[2] = 1; query[3] = 0;
            query[4] = 0; query[5] = 1;
            query[6] = 0; query[7] = 0;
            query[8] = 0; query[9] = 0;
            query[10] = 0; query[11] = 0;
            string[] tokens = name.Split(new char[] { '.' });
            string label;
            position = 12;
            for (int j = 0; j < tokens.Length; j++)
            {
                label = tokens[j];
                query[position++] = (byte)(label.Length & 0xFF);
                byte[] b = ASCII.GetBytes(label);
                for (int k = 0; k < b.Length; k++)
                {
                    query[position++] = b[k];
                }
            }
            query[position++] = 0; query[position++] = 0;
            query[position++] = 15; query[position++] = 0;
            query[position++] = 1;

            return query;
        }

        //for un packing the byte array 
        private List<MXRecord> makeResponse(byte[] response)
        {
            data = response;
            length = response.Length;

            //NOTE: we are ignoring the unnecessary fields. 
            // and takes only the data required to build MX records. 
            int qCount = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);
            if (qCount < 0)
            {
                throw new IOException("invalid question count");
            }
            int aCount = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);
            if (aCount < 0)
            {
                throw new IOException("invalid answer count");
            }
            position = 12;
            for (int i = 0; i < qCount; ++i)
            {
                name = "";
                position = proc(position);
                position += 4;
            }
            List<MXRecord> mxRecords = new List<MXRecord>();
            for (int i = 0; i < aCount; ++i)
            {
                name = "";
                position = proc(position);
                position += 10;
                int pref = (data[position++] << 8) | (data[position++] & 0xFF);
                name = "";
                position = proc(position);
                mxRecords.Add(new MXRecord
                {
                    preference = pref,
                    exchange = name
                });
            }
            return mxRecords;
        }

        private int proc(int position)
        {
            int len = (data[position++] & 0xFF);
            if (len == 0)
            {
                return position;
            }
            int offset;
            do
            {
                if ((len & 0xC0) == 0xC0)
                {
                    if (position >= length)
                    {
                        return -1;
                    }
                    offset = ((len & 0x3F) << 8) | (data[position++] & 0xFF);
                    proc(offset);
                    return position;
                }
                else {
                    if ((position + len) > length)
                    {
                        return -1;
                    }
                    name += ASCII.GetString(data, position, len);
                    position += len;
                }
                if (position > length)
                {
                    return -1;
                }
                len = data[position++] & 0xFF; 
                if (len != 0) { 
                    name += "."; 
                } 
            }while (len != 0); 
            return position; 
        } 
    } 
}