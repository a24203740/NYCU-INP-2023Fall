#include "solver.h"


void Solver::solve(int port)
{

    client.connectToServer("inp.zoolab.org", port);
    int mazeID = port - 10301;

    client.recvAppendToSS(200);
    clearOutHintMessage(mazeID);

    if(mazeID == 0 || mazeID == 1)
    {
        auto rawmap = readMap(mazeID);
        client.clearStreamBuffer();
        mapSolver.setMap(rawmap, sizeofMaze[mazeID][0], sizeofMaze[mazeID][1]);
        
        std::string answer = mapSolver.solve();
        client.sendToServer(answer);
        client.readMessage();
    }
    else if(mazeID == 2 || mazeID == 3)
    {
        mapSolver.initMap(400, 400);
        auto rawmap = readViewport(mazeID);
        client.clearStreamBuffer();
        
        mapSolver.mergeViewPortIntoMap(rawmap, mapSolver.getCurrentX(), mapSolver.getCurrentY(), 
                                                sizeofMaze[mazeID][0], sizeofMaze[mazeID][1]);
        bool firstRun = true;
        while(true)
        {
            std::string answer = mapSolver.solveByDFS(firstRun); firstRun = false;
            if(mazeID == 2)
            {
                answer+="R";
            }
            answer+="\n";
            std::cout << answer << std::endl;
            
            client.sendToServer(answer);
            if(mapSolver.hasMeetEnd())
            {
                client.readMessage();
                break;
            }
            else
            {
                client.recvAppendToSSUntilEnoughBytes(155);
                client.ingnoreLines(1);
                rawmap = readViewport(mazeID);
                client.clearStreamBuffer();

                mapSolver.mergeViewPortIntoMap(rawmap, mapSolver.getCurrentX(), mapSolver.getCurrentY(), 
                                                        sizeofMaze[mazeID][0], sizeofMaze[mazeID][1]);
                //std::cout << "Check" << std::endl;
            }

        }

    }
    client.closeConnection();

}

void Solver::clearOutHintMessage(int mazeID) {
    client.ingnoreLines(linesCountOfHintMessage[mazeID]);    
}



std::vector<std::vector<int>> Solver::readMap(int mazeID) {
    int width = sizeofMaze[mazeID][0], height = sizeofMaze[mazeID][1];
    std::vector<std::vector<int>> map(height);

    for(int r = 0; r < height; r++)
    {
        map[r] = convertStringToOneRowOfMaze(client.readOneLine(), width);
    }
    return map;
}

std::vector<int> Solver::convertStringToOneRowOfMaze(const std::string& line, int width){
    std::vector<int> row(width);
    for (int i = 0; i < width; i++)
    {
        if(line[i] == '#')
        {
            row[i] = 0;
        }
        else if(line[i] == '.')
        {
            row[i] = 1;
        }
        else if(line[i] == '*') // 2 = start
        {
            row[i] = 2;
        }
        else if(line[i] == 'E') // 3 = end
        {
            row[i] = 3;
        }
        else
        {
            std::cerr << "Error reading map!"<< std::endl;
            std::cerr << "invalid char: " << (int)line[i] << " at " << i << std::endl;
            return std::vector<int>();
        }
    }
    return row;
}

std::vector<int> Solver::convertStringToOneRowOfMaze(
        const std::string& line, int viewportWidth, int actualWidth, int offset){
    std::vector<int> row(viewportWidth, -1);
    for (int i = 0; i < actualWidth; i++)
    {
        if(line[i + offset] == '#')
        {
            row[i] = 0;
        }
        else if(line[i + offset] == '.')
        {
            row[i] = 1;
        }
        else if(line[i + offset] == '*') // 2 = start
        {
            row[i] = 2;
        }
        else if(line[i + offset] == 'E') // 3 = end
        {
            row[i] = 3;
        }
        else if(line[i + offset] == ' ')
        {
            row[i] = -1;
        }
        else
        {
            std::cerr << "Error reading map!"<< std::endl;
            std::cerr << "invalid char: " << (int)line[i + offset] << " at " << i+offset << std::endl;
            return std::vector<int>();
        }
    }
    return row;
}


std::vector<std::vector<int>> Solver::readViewport(int mazeID) {
    int offset = 7;
    int viewportWidth = sizeofMaze[mazeID][0], viewportHeight = sizeofMaze[mazeID][1];
    std::vector<std::vector<int>> viewport(viewportHeight);
    std::string viewportRow;
    for(int r = 0; r < viewportHeight; r++)
    {
        viewportRow = client.readOneLine();
        //std::cout << viewportRow << std::endl;
        //std::cout << viewportRow << " " << viewportRow.size() << std::endl;
        int actualWidth = viewportRow.size() - offset;
        viewport[r] = convertStringToOneRowOfMaze(viewportRow, viewportWidth, actualWidth, offset);
        
        if(viewport[r].empty())
        {
            std::cout << "failed" << std::endl;
            r--;
            continue;
        }

        // for(auto x: viewport[r])
        // {
        //     std::cout << x << " ";
        // }
        // std::cout << std::endl;
    }
    return viewport;
}
