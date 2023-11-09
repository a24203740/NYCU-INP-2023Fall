#include "Client.h"

class HTTPclient
{
    Client* client;
    std::string OTP;
    std::string parsedOTP;
    void connect();
    void sendRequest(std::string req);
    void sendGETotpRequest(std::string id);
    void receiveOTP();
    void processOTP();
public:
    HTTPclient();
    ~HTTPclient();
    std::string getOTP(std::string id);
    void showVerfyOTP();
    void uploadOTP();
    void closeConnection();
};