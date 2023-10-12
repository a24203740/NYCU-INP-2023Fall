#include <fstream>
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <exception>
#include <iterator>
#include <iomanip>

class BinParser
{
    std::ifstream file;
    std::vector<unsigned char> data;
    void loadFile(std::string filename)
    {
        file.open(filename, std::ios::binary);
        if(!file)
        {
            throw std::logic_error("unable to open file");
        }
    }
    void copyFileIntoVector()
    {
        // first is begin of file iterator, last is so called "end of stream" iterator
        data = std::vector<unsigned char>(std::istreambuf_iterator<char>(file),
                                            std::istreambuf_iterator<char>());
    }
    void close()
    {
        file.close();
    }
public:
    std::vector<unsigned char> parse(std::string name)
    {
        loadFile(name);
        copyFileIntoVector();
        close();
        return data;
    }
};

class ChallengeParser
{
    const int   DICT_SIZE_OFFSET=8, BLOCK_COUNT_OFFSET=12,
                FIRST_BLOCK_OFFSET=16, BLOCK_HEADER_OFFSET=8, 
                FLAG_HEADER_OFFSET=2;

    int FLAG_START_OFFSET;

    std::vector<unsigned char> data;
    std::vector<unsigned char> Dict;
    struct Header { 
        //uint64_t magic;     /* 'BINFLAG\x00' */   0-7
        //uint32_t datasize;  /* in big-endian */   8-11
        //uint16_t n_blocks;  /* in big-endian */   12-13
        //uint16_t zeros;                           14-15
        
        int dictSize; // data[8-11]
        int blockCount;// data[12-13]
    }header;

    struct Block {
        // uint32_t offset;        /* in big-endian */
        // uint16_t cksum;         /* XOR'ed results of each 2-byte unit in payload */
        // uint16_t length;        /* ranges from 1KB - 3KB, in big-endian */
        // uint8_t  payload[0];

        int offset;
        int cksum;
        int length;
        std::vector<int> payload;
    };
    std::vector<Block> blocksList;

    struct Flag {
        // uint16_t length;        /* length of the offset array, in big-endian */
        // uint32_t offset[0];     /* offset of the flags, in big-endian */

        int length;
        std::vector<int> offset;
    }flag;
public:

    static bool blockCompare(const Block& b1, const Block& b2)
    {
        return b1.offset < b2.offset;
    }

    void setData(std::vector<unsigned char> _data)
    {
        data = _data;
        std::cout << data.size() << std::endl;
        for(int i = 0; i < data.size(); i++)
        {
            if(i != 0 && i % 16 == 0)
            {
                std::cout << '\n';
            }
            else if(i != 0 && i % 8 == 0)
            {
                std::cout << ' ';
            }
            std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)data[i] << ' ';
        }
        std::cout << std::dec << '\n';
    }
    long long int valueOfBigEndianExpress(int start, int end)
    {
        long long int value = 0;
        for(int i = start; i <= end; i++)
        {
            value *= 256;
            value += data[i];
        }
        return value;
    }

    void headerParser()
    {
        header.dictSize=valueOfBigEndianExpress(8, 11);
        header.blockCount=valueOfBigEndianExpress(12, 13);
        std::cout << "Dict size " << header.dictSize << " & Block Count " << header.blockCount << std::endl; 
    }
    Block blockHeaderParser(Block b, int curOffset)
    {
        b.offset=valueOfBigEndianExpress(curOffset, curOffset+3);
        b.cksum=valueOfBigEndianExpress(curOffset+4, curOffset+5);
        b.length=valueOfBigEndianExpress(curOffset+6, curOffset+7);

        // output block header
        std::cout << "Block Header: " << std::endl;
        std::cout << "Offset: " << b.offset << std::endl;
        std::cout << "Cksum: " << b.cksum << std::endl;
        std::cout << "Length: " << b.length << std::endl;


        return b;
    }
    Block blockPayloadParser(Block b, int curOffset)
    {
        b.payload.resize(b.length);
        for(int i = 0; i < b.length; i++)
        {
            b.payload[i] = data[curOffset+i];
            
        }
        return b;
    }
    bool verfifyByCksum(const Block& b)
    {
        int XOR_val = 0;
        for(int i = 0; i < b.length; i+=2)
        {
            XOR_val = XOR_val ^ ((b.payload[i] << 8) | b.payload[i+1]);
        }
        return XOR_val == b.cksum;
    }
    void blocksParser()
    {
        blocksList.clear();

        int currentBlockStart = FIRST_BLOCK_OFFSET;
        for(int i = 0; i < header.blockCount; i++)
        {
            std::cout << "Block #" << i << std::endl;
            Block b;
            
            b = blockHeaderParser(b, currentBlockStart);
            b = blockPayloadParser(b, currentBlockStart+BLOCK_HEADER_OFFSET);
            
            if(verfifyByCksum(b))
            {
                std::cout << "Valid Block" << std::endl;
                blocksList.push_back(b);
            }
            else
            {
                std::cout << "Invalid Block" << std::endl;
            }

            currentBlockStart += BLOCK_HEADER_OFFSET + b.length;
        }
        FLAG_START_OFFSET = currentBlockStart;

        sort(blocksList.begin(), blocksList.end(), ChallengeParser::blockCompare);
    }

    void dictConstructor()
    {
        Dict.resize(header.dictSize);
        for(int i = 0; i < blocksList.size(); i++)
        {
            int offset = blocksList[i].offset;
            
            std::cout << "offset = " << offset << " and length = " << blocksList[i].length << std::endl;
            for(int j = 0; j < blocksList[i].length; j++)
            {
                Dict[offset+j] = blocksList[i].payload[j];
            }
        }
        for(int i = 0; i < Dict.size(); i++)
        {
            if(i != 0 && i % 16 == 0)
            {
                std::cout << '\n';
            }
            else if(i != 0 && i % 8 == 0)
            {
                std::cout << ' ';
            }
            std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)Dict[i] << ' ';

        }
        std::cout << std::dec << '\n';
    }

    void FlagParser()
    {
        flag.length=valueOfBigEndianExpress(FLAG_START_OFFSET, FLAG_START_OFFSET+1);
        flag.offset.resize(flag.length);


        std::cout << "Flag Length: " << flag.length << std::endl;

        std::cout << "Flag Offset: " << std::endl;
        for(int i = 0; i < flag.length; i++)
        {
            flag.offset[i] = valueOfBigEndianExpress(FLAG_START_OFFSET+FLAG_HEADER_OFFSET+(i*4), FLAG_START_OFFSET+FLAG_HEADER_OFFSET+(i*4+3));
            std::cout << flag.offset[i] << std::endl;
        }
    }

    void decode()
    {
        std::fstream output("output/flag", std::ios::out);
        for(int i = 0; i < flag.length; i++)
        {
            output << std::setw(2) << std::setfill('0') << std::hex << (int)(Dict[flag.offset[i]]);
            output << std::setw(2) << std::setfill('0') << std::hex << (int)(Dict[flag.offset[i]+1]);
        }
        output.close();
    }
};

int main()
{
    BinParser binParser;
    auto data = binParser.parse("input/input.bin");

    ChallengeParser cp;
    cp.setData(data);
    cp.headerParser();
    cp.blocksParser();
    cp.FlagParser();
    cp.dictConstructor();
    cp.decode();
}