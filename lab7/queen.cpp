#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>
#include <utility>
#include "queen.h"

const int rowSize = 30;
const int colSize = 30;

inline void errquit(const char *msg) {
    perror(msg);
    exit(-1);
}

std::vector<bool> rowHasQueen(rowSize, false);
std::vector<bool> colHasQueen(colSize, false);
std::vector<bool> diagHasQueen(rowSize + colSize - 1, false);
std::vector<bool> antiDiagHasQueen(rowSize + colSize - 1, false);

std::vector<std::pair<int, int>> queenPos(30, std::make_pair(-1, -1));

void placeQueen(int row, int col) {
    rowHasQueen[row] = true;
    colHasQueen[col] = true;
    diagHasQueen[row + col] = true;
    antiDiagHasQueen[row - col + colSize - 1] = true;
}

void removeQueen(int row, int col) {
    rowHasQueen[row] = false;
    colHasQueen[col] = false;
    diagHasQueen[row + col] = false;
    antiDiagHasQueen[row - col + colSize - 1] = false;
}

bool isSafe(int row, int col)
{
    return !colHasQueen[col] && 
             !diagHasQueen[row + col] && 
             !antiDiagHasQueen[row - col + colSize - 1];
}

void initBoard(std::vector<std::vector<int>> board)
{
    for(int r = 0; r < rowSize; r++) {
        for(int c = 0; c < colSize; c++) {
            if(board[r][c] == 1) 
            {
                placeQueen(r, c);
                printf("Queen at (%d,%d)\n", r, c);
            }
        }
    }
}
 
// A recursive utility function to solve N
// Queen problem
bool solveNQUtil(int row)
{
    static int count = 0;
    count++;
    if(count > 1000000)
    {
        printf("Haven't died\n");
        fflush(stdout);
        count = 0;
    }
    if(row >= rowSize) return true;
    if(rowHasQueen[row]) return solveNQUtil(row + 1);
 
    for(int col = 0; col < colSize; col++)
    {
        if(isSafe(row, col))
        {
            queenPos[row] = std::make_pair(row, col);
            placeQueen(row, col);
            if(solveNQUtil(row + 1)) return true;
            removeQueen(row, col);
            queenPos[row] = std::make_pair(-1, -1);
        }
    }
    return false;
}

int main() {
    int sockfd;
    struct sockaddr_un serv_addr;
    char buffer[3000];
    std::vector<std::vector<int>> board;
    
    connectToUnixSocket(sockfd, serv_addr, "/queen.sock");
    if(sockfd < 0) errquit("socket error");
    printf("Connected to server\n");
    fflush(stdout);
    sleep(1);
    write(sockfd, "S\n\0", 3);
    printf("Sent: %s\n", "S");

    int readByte = read(sockfd, buffer, sizeof(buffer));
    printf("Received:\n%s\n", buffer);

    for(int r = 0; r < rowSize; r++) {
        board.push_back(std::vector<int>());
        std::vector<int>& row = board.back();
        for(int c = 0; c < colSize; c++) {
            int index = r * colSize + c + 4;
            char word = buffer[index];
            if(word == '.')
            {
                row.push_back(0);
            }
            else if(word == 'Q')
            {
                row.push_back(1);
            }
            else
            {
                row.push_back(-1);
                fprintf(stderr, "Error: %c at (%d,%d)\n", word, r, c);
            }
        }
    }

    for(int r = 0; r < rowSize; r++) {
        for(int c = 0; c < colSize; c++) {
            printf("%d ", board[r][c]);
        }
        printf("\n");
    }
    fflush(stdout);
    initBoard(board);
    if(solveNQUtil(0))
    {
        printf("Found solution!\n");
        for(int i = 0; i < queenPos.size(); i++)
        {
            printf("(%d,%d)\n", queenPos[i].first, queenPos[i].second);
        }
    }
    char msg[100];
    for(int i = 0; i < queenPos.size(); i++)
    {
        if(queenPos[i].first == -1) continue;
        sprintf(msg, "M %d %d\n", queenPos[i].first, queenPos[i].second);
        write(sockfd, msg, strlen(msg));
        printf("Sent: %s\n", msg);
        sleep(0.1);
        readByte = read(sockfd, buffer, sizeof(buffer));
        printf("Received:\n%s\n", buffer);
    }
    write(sockfd, "C\n", 2);
    readByte = read(sockfd, buffer, sizeof(buffer));
    printf("Received:\n%s\n", buffer);
    close(sockfd);

    return 0;
}
int connectToUnixSocket(int &sockfd, sockaddr_un &serv_addr, const char* socketPath)
{
    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        perror("socket error");
        return -1;
    }

    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    strcpy(serv_addr.sun_path, socketPath);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("connect error");
        return -1;
    }
    return sockfd;
}