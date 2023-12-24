#include <string>
#include <vector>
#include <utility>
#include <map>
#include <unordered_map>
#include <memory>

struct User
{
    std::string username;
    std::string password;
    std::string status;
    int loginFD;
    int chatRoomNumber;
    bool isLogin;
    bool isChatting;
    User(std::string username, std::string password)
    {
        this->username = username;
        this->password = password;
        this->status = "offline";
        this->loginFD = -1;
        this->chatRoomNumber = -1;
        this->isLogin = false;
        this->isChatting = false;
    }
};

class UserManager
{
    std::map<std::string, std::shared_ptr<User>> usernameLookupTable;
    std::map<int, std::shared_ptr<User>> FDtoLoginUserLookupTable;

public:
    bool checkUsernameExists    (std::string username);
    bool checkPasswordCorrect   (std::string username, std::string password);
    bool checkUserIsLogin       (int clientFD);
    bool checkUserIsLogin       (std::string username);
    bool checkUserIsChatting    (int clientFD);
    bool checkUserIsChatting    (std::string username);

    void registerNewUser(std::string username, std::string password);
    void clientLogin    (std::string username, int clientFD);
    void clientLogout   (int clientFD);
    void clientJoinChatRoom(int clientFD, int chatRoomNumber);
    void clientLeaveChatRoom(int clientFD);

    std::string getUsername         (int clientFD);
    std::string getStatus           (std::string username);
    std::string getStatus           (int clientFD);
    int         getChatRoomNumber   (std::string username);
    int         getChatRoomNumber   (int clientFD);

    std::vector<std::string> getUserList();

    void setUserStatus(int clientFD, std::string status);
    void setUserStatus(std::string username, std::string status);
    
};