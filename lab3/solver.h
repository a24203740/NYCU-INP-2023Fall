#include "Client.h"
#include "MapSolver.h"

class Solver
{
    Client client;
    MapSolver mapSolver;
    int sizeofMaze[4][2] = {{11, 7}, {79, 21}, {11, 7}, {11, 7}};
    const int linesCountOfHintMessage[4] = {9, 8, 11, 8};
    
    void clearOutHintMessage(int mazeID);
    std::vector<int> convertStringToOneRowOfMaze(const std::string& line, int width);
    std::vector<int> convertStringToOneRowOfMaze(const std::string& line, int viewportWidth, int actualWidth, int offset);
    std::vector<std::vector<int>> readMap(int mazeID);
    std::vector<std::vector<int>> readViewport(int mazeID);
    

public: 
    void solve(int port);

};