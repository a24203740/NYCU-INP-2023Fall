#include "HTTPclient.h"


HTTPclient::HTTPclient() {
    client = new Client();
}

HTTPclient::~HTTPclient() {
    closeConnection();
}

void HTTPclient::sendRequest(std::string req) {
    client->sendToServer(req);
}

void HTTPclient::closeConnection() {
    client->closeConnection();
}

void printRequestString(std::string str)
{
    for(auto &c : str)
    {
        if(c == '\r') c = ' ';
    }
    std::cout << str << std::endl;
}

void HTTPclient::sendGETotpRequest(std::string id) {
    
    std::string req = "GET /otp?name="+ id + " HTTP/1.1\r\nHost: inp.zoolab.org\r\n\r\n";
    std::cout << "send GET request: " << std::endl;
    printRequestString(req);
    client->sendToServer(req);
}

void HTTPclient::receiveOTP() {
    client->clearStreamBuffer();
    client->recvAppendToSSUntilEnoughBytes(270);
    client->ingnoreLines(7);
    OTP = client->readOneLine();
}

std::string HTTPclient::getOTP(std::string id) {
    connect();
    sendGETotpRequest(id);
    receiveOTP();
    processOTP();
    closeConnection();
    return OTP;
}

void HTTPclient::connect() {
    //client->connectToServer("inp.zoolab.org", 10314);    
    client->connectToServerWithRawIP("172.21.0.4", 10001);    
}

void HTTPclient::processOTP()
{
    int otpSize = OTP.size();
    parsedOTP = OTP;
    for(int i = 0; i < otpSize; i++)
    {
        if(parsedOTP[i] == '+')
        {
            parsedOTP=parsedOTP.substr(0, i) + "%2B" + parsedOTP.substr(i+1, otpSize - i - 1);
            otpSize = parsedOTP.size();
            std::cout << "New OPT: " << parsedOTP << std::endl;
        }
        if(parsedOTP[i] == '=')
        {
            parsedOTP=parsedOTP.substr(0, i) + "%3D" + parsedOTP.substr(i+1, otpSize - i - 1);
            otpSize = parsedOTP.size();
            std::cout << "New OPT: " << parsedOTP << std::endl;
        }
    }
}

void HTTPclient::showVerfyOTP() {
    connect();
    std::string req = "GET /verify?otp=" + parsedOTP + " HTTP/1.1\r\nHost: inp.zoolab.org\r\n\r\n";
    std::cout << "send verify request: " << req;
    client->clearStreamBuffer();
    client->sendToServer(req);
    client->recvAppendToSSUntilEnoughBytes(165);
    for(int i = 0; i < 8; i++)
    {
        std::cout << client->readOneLine() << std::endl;
    }
    std::cout << client->readOneLine() << std::endl;
    closeConnection();
}

void HTTPclient::uploadOTP() {
    std::string reqMIMEcontent = 
        "------TwFouRTwoIsLove\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"OTP.txt\"\r\n"
        "\r\n";

    std::string reqFooter = 
        "\r\n"
        "------TwFouRTwoIsLove--\r\n";

    std::string dataLength = std::to_string(OTP.size() + reqMIMEcontent.size() + reqFooter.size());
    std::string reqHeader =
        "POST /upload HTTP/1.1\r\n"
        "Host: inp.zoolab.org:10314\r\n"
        "Content-Length: "+ dataLength +"\r\n"
        "Content-Type: multipart/form-data; boundary=----TwFouRTwoIsLove\r\n"
        "\r\n";
    std::cout << "send upload req: " << std::endl;
    printRequestString(reqHeader + reqMIMEcontent + OTP + reqFooter);
    std::cout << "data length" << dataLength << std::endl;
    connect();
    client->clearStreamBuffer();
    client->sendToServer(reqHeader + reqMIMEcontent + OTP + reqFooter);
    client->recvAppendToSSUntilEnoughBytes(156); // 165 for public server
    for(int i = 0; i < 8; i++)
    {
        printRequestString(client->readOneLine());
    }
    closeConnection();
}
