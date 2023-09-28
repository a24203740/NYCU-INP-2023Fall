/*

    This code is used for INP fall 2023 lab 1
    author is TwoFourTwo (hsuchy)

    Usage of code must follow YCIFH-IPYTD license

    YCIFLS-IPYUYBM license:
        You Copy It For Lab Submission, I Punch You Until You Become Mesh


*/
#include <string>
#include <iostream>
// to compile it, you need to add -lpcap
#include <pcap/pcap.h>
#include <iomanip> 
#include <vector>

using namespace std;

struct packetInfo
{
    int packetSeqNumber;
    int captureLen;
    int expectedLen;
    timeval timestamp; // mem: tv_sec, tv_usec
    int ipHeaderLength;
    int UDPpayloadLength;
    bool isBeginFlag;
    bool isEndFlag;

    packetInfo()
    {
        packetSeqNumber = -1;
        captureLen = 0;
        expectedLen = 0;
        ipHeaderLength = 0;
        UDPpayloadLength = 0;
        isBeginFlag = 0;
        isEndFlag = 0;
    }
};
class parser
{
    char errorBuffer[PCAP_ERRBUF_SIZE];

    pcap_t * pcapHandler;
    bool handlerValid;
    
    int packetNumber;
    bool verbose;

    vector<packetInfo> packetInfoList;
    int beginSeqNum;
    int endSeqNum;

    void printPacket_Size(int captureLen, int expectedLen)
    {
        cout << "Packet size: " << captureLen << " bytes " << endl;
        if (captureLen != expectedLen)
        {
            cout    << "Warning! Capture size is different than expected packet size: " 
                    << expectedLen << " bytes " << endl;
        }
    }
    void parsePacket_Size(const pcap_pkthdr* Header, packetInfo& currentPacketInfo)
    {
        currentPacketInfo.captureLen = Header->caplen;
        currentPacketInfo.expectedLen = Header->len;

        if(verbose)
        {
            printPacket_Size(currentPacketInfo.captureLen, currentPacketInfo.expectedLen);
        }
    }
    
    void printPacket_TimeStamp(int second, int microSecond)
    {
        cout << "Epoch Time: " << second << ":" << microSecond << " seconds" << endl;
    }
    void parsePacket_TimeStamp(const pcap_pkthdr* Header, packetInfo& currentPacketInfo)
    {
        currentPacketInfo.timestamp = Header->ts;

        if(verbose)
        {
            printPacket_TimeStamp(currentPacketInfo.timestamp.tv_sec, currentPacketInfo.timestamp.tv_usec);
        }
    }

    void parsePacket_pcapHeader(const pcap_pkthdr* Header, packetInfo& currentPacketInfo)
    {
        parsePacket_Size(Header, currentPacketInfo);
        parsePacket_TimeStamp(Header, currentPacketInfo);
    }

    void parsePacket_IPHeaderLength(const u_char* Data, packetInfo& currentPacketInfo)
    {
        int IPPacketStart = 20;
        // 20th byte is ip.hdr_len, but first half byte is IP version, second half byte is IP header length
        // and, for example, if the second half byte is 5, than it means IP header is 5 * 4 = 20 bytes long.
        int IPheaderLength = (int(Data[IPPacketStart]) % 16) * 4;
        currentPacketInfo.ipHeaderLength = IPheaderLength;
        if(verbose)
        {
            cout << "IP header Length is " << IPheaderLength << endl;
        }
    }
    void parsePacket_UDPpayloadLength(const u_char* Data, packetInfo& currentPacketInfo, int UDPpacketStart)
    {
        // fifth and sixth byte in UDP header store UDP packet length, include header
        // and UDP header is 8 bytes;
        int UDPHeaderLengthFieldStart = UDPpacketStart + 4;

        currentPacketInfo.UDPpayloadLength = 
            int(Data[UDPHeaderLengthFieldStart]) * 256 + int(Data[UDPHeaderLengthFieldStart + 1]) - 8;

        if(verbose)
        {
            cout << "UDP payload Length is " << currentPacketInfo.UDPpayloadLength << endl;
        }
    }

    void parsePacket_SeqNumber(const u_char* Data, packetInfo& currentPacketInfo, int UDPpayloadStart)
    {
        int sequenceNumber =    (int(Data[UDPpayloadStart + 4]) - '0') * 10000
                            +   (int(Data[UDPpayloadStart + 5]) - '0') * 1000
                            +   (int(Data[UDPpayloadStart + 6]) - '0') * 100
                            +   (int(Data[UDPpayloadStart + 7]) - '0') * 10
                            +   (int(Data[UDPpayloadStart + 8]) - '0') * 1;
        
        currentPacketInfo.packetSeqNumber = sequenceNumber;

        if(verbose)
        {
            cout << "Sequence Number is " << currentPacketInfo.packetSeqNumber << endl;
        }
    }
    void parsePacket_FlagBegin(const u_char* Data, packetInfo& currentPacketInfo, int UDPpayloadStart)
    {
         currentPacketInfo.isBeginFlag = Data[UDPpayloadStart + 10] == 'B';

         if(verbose && currentPacketInfo.isBeginFlag)
         {
            cout << "This packet is begin flag" << endl;
         }
    }
    void parsePacket_FlagEnd(const u_char* Data, packetInfo& currentPacketInfo, int UDPpayloadStart)
    {
         currentPacketInfo.isEndFlag = Data[UDPpayloadStart + 10] == 'E';

         if(verbose && currentPacketInfo.isEndFlag)
         {
            cout << "This packet is End flag" << endl;
         }
    }
    void parsePacket_Payload(const u_char* Data, packetInfo& currentPacketInfo, int UDPpacketStart)
    {
        int UDPpayloadStart = UDPpacketStart + 8;

        if(currentPacketInfo.UDPpayloadLength <= 10)
        {
            cout << "[WARRNING]: not a valid packet" << endl;
            return;
        }

        parsePacket_SeqNumber(Data, currentPacketInfo, UDPpayloadStart);
        parsePacket_FlagBegin(Data, currentPacketInfo, UDPpayloadStart);
        parsePacket_FlagEnd(Data, currentPacketInfo, UDPpayloadStart);
    }
    
    void parsePacket_pcapData(const u_char* Data, packetInfo& currentPacketInfo)
    {
        parsePacket_IPHeaderLength(Data, currentPacketInfo);
        int UDPpacketStart = 20 + currentPacketInfo.ipHeaderLength;
        parsePacket_UDPpayloadLength(Data, currentPacketInfo, UDPpacketStart);
        parsePacket_Payload(Data, currentPacketInfo, UDPpacketStart);
    }
    
    bool checkAndPutNextPacketIntoBuffer(const u_char*& DataBuffer, pcap_pkthdr*& HeaderBuffer)
    {
        // get next packet, store data into 2 buffer
        // return number < 0 if no packet remain
        return pcap_next_ex(pcapHandler, &HeaderBuffer, &DataBuffer) >= 0; 
    }

    void parseThroughAllPacket()
    {
        pcap_pkthdr*    packetHeaderBuffer;
        const u_char*   packetDataBuffer;

        while (checkAndPutNextPacketIntoBuffer(packetDataBuffer, packetHeaderBuffer))
        {
            if(verbose)
            {
                cout << "Packet Number: " << ++packetNumber << endl;
            }

            packetInfo currentPacketInfo;
            parsePacket_pcapHeader(packetHeaderBuffer, currentPacketInfo);
            parsePacket_pcapData(packetDataBuffer, currentPacketInfo);

            if(currentPacketInfo.isBeginFlag)   beginSeqNum = currentPacketInfo.packetSeqNumber;
            if(currentPacketInfo.isEndFlag)     endSeqNum   = currentPacketInfo.packetSeqNumber;
            packetInfoList.push_back(currentPacketInfo);

            if(verbose)
            {
                cout << "======================" << endl;
            }
        }
    }

    void assembleFlag()
    {
        int flagSize = endSeqNum - beginSeqNum - 1;
        vector<char> flag(flagSize);
        for(const auto& info : packetInfoList)
        {
            if(info.packetSeqNumber > beginSeqNum && info.packetSeqNumber < endSeqNum)
            {
                flag[info.packetSeqNumber - beginSeqNum - 1] = 
                    info.UDPpayloadLength + info.ipHeaderLength - 20;
            }
        }
        for(int i = 0; i < flagSize; i++)
        {
            cout << flag[i];
        }
        cout << '\n';
    }

    void createHandler(string filename)
    {
        pcapHandler = pcap_open_offline(filename.c_str(), errorBuffer);
        handlerValid = true;
    }
    void closeHandler()
    {
        pcap_close(pcapHandler);
        handlerValid = false;
    }

public:

    parser()
    {
        pcapHandler = nullptr;
        packetNumber = 0;
        handlerValid = false;
        verbose = true;

        packetInfoList.clear();
        beginSeqNum = 0;
        endSeqNum = 0;
    }

    void plzJustShutUp()
    {
        verbose = false;
    }

    void start(string filename)
    {
        createHandler(filename);
        parseThroughAllPacket();
        assembleFlag();
        closeHandler();
    }
};

int main(int argc, char *argv[])
{
    /*
    * Step 2 - Get a file name
    */
    if(argc != 2)
    {
        cout << "usage: PCAPparser <filename>" << endl;
        return -1;
    }
    string file = string(argv[1]);
 
    parser parserInstance;
    parserInstance.start(file);
}