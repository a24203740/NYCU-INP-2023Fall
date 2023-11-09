#include "HTTPclient.h"
#include <fstream>
int main(int argc, char* argv[]) {
    
    // std::cout << "HI?" << std::endl;
    HTTPclient hc;

    //std::ofstream file("./OTP.txt");
    hc.getOTP("110550075");
    //file.close();
    
    //hc.showVerfyOTP();
    hc.uploadOTP();
    /*
    Client client;
    client.connectToServer("inp.zoolab.org", 10314);
    //client.recvAppendToSSUntilEnoughBytes(5);
    //client.readMessage();
    std::string req = "GET /otp?name=110550075 HTTP/1.1\r\nHost: inp.zoolab.org\r\n\r\n";
    client.sendToServer(req);
    client.readMessage();
    client.closeConnection();
    */
    return 0;
}