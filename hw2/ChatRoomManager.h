#include <string>
#include <vector>
#include <deque>
#include <utility>
#include <map>
#include <set>
#include <memory>

struct messageHistory
{
    std::string sender;
    std::string message;
    messageHistory()
    {
        this->sender = "";
        this->message = "";
    }
    messageHistory(std::string sender, std::string message)
    {
        this->sender = sender;
        this->message = message;
    }
};


struct chatRoom
{
    int chatRoomNumber;
    std::string ownerName;
    std::set<int> clientFDset;
    std::deque<messageHistory> chatHistory;
    std::string pinMessage;
    bool hasPinMessage;
    chatRoom(int chatRoomNumber, std::string ownerName)
    {
        this->chatRoomNumber = chatRoomNumber;
        this->ownerName = ownerName;
        this->clientFDset = std::set<int>();
        this->chatHistory = std::deque<messageHistory>();
        this->pinMessage = "";
        this->hasPinMessage = false;
    }
};

class ChatRoomManager
{
    std::map<int, std::shared_ptr<chatRoom>> chatRoomNumberLookupTable;
    const int MAX_CHAT_HISTORY = 10;
public:
    bool checkChatRoomNumberExists(int chatRoomNumber);
    bool checkUserIsOwner(std::string username, int chatRoomNumber);
    bool checkRoomHasPinMessage(int chatRoomNumber);
    bool checkChatHistoryIsEmpty(int chatRoomNumber);

    void createNewChatRoom(int chatRoomNumber, std::string ownerName);
    void deleteChatRoom(int chatRoomNumber);
    void clientJoinChatRoom(int chatRoomNumber, int clientFD);
    void clientLeaveChatRoom(int chatRoomNumber, int clientFD);
    void pinMessage(int chatRoomNumber, std::string message);
    void deletePinMessage(int chatRoomNumber);
    void addMessageToChatHistory(int chatRoomNumber, std::string sender, std::string message);

    std::string getOwnerName(int chatRoomNumber);
    std::set<int> getClientInRoom(int chatRoomNumber);
    std::deque<messageHistory> getChatHistory(int chatRoomNumber);
    std::string getPinMessage(int chatRoomNumber);

    std::vector<int> getChatRoomList();
};


