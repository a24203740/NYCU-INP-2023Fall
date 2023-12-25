#include "ChatRoomManager.h"


bool ChatRoomManager::checkChatRoomNumberExists(int chatRoomNumber) 
{
    return chatRoomNumberLookupTable.find(chatRoomNumber) != chatRoomNumberLookupTable.end();
}

bool ChatRoomManager::checkUserIsOwner(std::string username, int chatRoomNumber) 
{
    return chatRoomNumberLookupTable[chatRoomNumber]->ownerName == username;
}

bool ChatRoomManager::checkRoomHasPinMessage(int chatRoomNumber) 
{
    return chatRoomNumberLookupTable[chatRoomNumber]->hasPinMessage;
}

bool ChatRoomManager::checkChatHistoryIsEmpty(int chatRoomNumber) 
{
    return chatRoomNumberLookupTable[chatRoomNumber]->chatHistory.empty();
}

void ChatRoomManager::createNewChatRoom(int chatRoomNumber, std::string ownerName) 
{
    chatRoomNumberLookupTable[chatRoomNumber] = std::make_shared<chatRoom>(chatRoomNumber, ownerName);
}

void ChatRoomManager::deleteChatRoom(int chatRoomNumber) 
{
    chatRoomNumberLookupTable.erase(chatRoomNumber);
}

void ChatRoomManager::clientJoinChatRoom(int chatRoomNumber, int clientFD) 
{
    chatRoomNumberLookupTable[chatRoomNumber]->clientFDset.insert(clientFD);
}

void ChatRoomManager::clientLeaveChatRoom(int chatRoomNumber, int clientFD) 
{
    chatRoomNumberLookupTable[chatRoomNumber]->clientFDset.erase(clientFD);
}

void ChatRoomManager::pinMessage(int chatRoomNumber, std::string message) 
{
    chatRoomNumberLookupTable[chatRoomNumber]->pinMessage = message;
    chatRoomNumberLookupTable[chatRoomNumber]->hasPinMessage = true;
}

void ChatRoomManager::deletePinMessage(int chatRoomNumber) 
{
    chatRoomNumberLookupTable[chatRoomNumber]->pinMessage = "";
    chatRoomNumberLookupTable[chatRoomNumber]->hasPinMessage = false;
}

void ChatRoomManager::addMessageToChatHistory(int chatRoomNumber, std::string sender, std::string message) 
{
    chatRoomNumberLookupTable[chatRoomNumber]->chatHistory.push_back(messageHistory(sender, message));
    while(chatRoomNumberLookupTable[chatRoomNumber]->chatHistory.size() > MAX_CHAT_HISTORY)
    {
        chatRoomNumberLookupTable[chatRoomNumber]->chatHistory.pop_front();
    }
}

std::string ChatRoomManager::getOwnerName(int chatRoomNumber) 
{
    return chatRoomNumberLookupTable[chatRoomNumber]->ownerName;
}

std::set<int> ChatRoomManager::getClientInRoom(int chatRoomNumber) 
{
    return chatRoomNumberLookupTable[chatRoomNumber]->clientFDset;
}

std::deque<messageHistory> ChatRoomManager::getChatHistory(int chatRoomNumber) 
{
    return chatRoomNumberLookupTable[chatRoomNumber]->chatHistory;
}

std::string ChatRoomManager::getPinMessage(int chatRoomNumber) 
{
    return chatRoomNumberLookupTable[chatRoomNumber]->pinMessage;
}

std::vector<int> ChatRoomManager::getChatRoomList() 
{
    std::vector<int> chatRoomList;
    for(auto& pair : chatRoomNumberLookupTable)
    {
        chatRoomList.push_back(pair.first);
    }
    return chatRoomList;
}
