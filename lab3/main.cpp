#include "solver.h"

int sizeofMap[4][2] = {{11, 7}, {79, 21}, {11, 7}, {11, 7}};

int main(int argc, const char *argv[])
{
    if(argc != 2)return 1;
    int portNumber = atoi(argv[1]);
    
    Solver solver;
    solver.solve(portNumber);

/*
    auto map = client.readMap(sizeofMap[mapNumber][0], sizeofMap[mapNumber][1]);
    // print map
    for (int i = 0; i < sizeofMap[mapNumber][1]; i++)
    {
        for (int j = 0; j < sizeofMap[mapNumber][0]; j++)
        {
            std::cout << map[i][j];
        }
        std::cout << std::endl;
    }

    MapSolver solver;
    solver.setMap(map, sizeofMap[mapNumber][0], sizeofMap[mapNumber][1]);
    auto solution = solver.solve();
    for(auto c : solution)
    {
        std::cout << c;
    }
    client.sendSolution(solution);
*/
}