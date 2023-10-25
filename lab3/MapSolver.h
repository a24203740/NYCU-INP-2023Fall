#include <string>
#include <vector>
#include <queue>
#include <stack>
#include <utility>
#include <iostream>
#include <iomanip>

class MapSolver {

    enum
    {
        UNKNOWN = -2,
        VOID = -1,
        WALL = 0,
        PATH = 1,
        START = 2,
        END = 3
    };

    struct Point
    {
        int x;
        int y;
        Point();
        Point(int _x, int _y);
    };
    struct MapEntry
    {
        int type;
        int distance;
        Point prev;
    };
    struct DFSEnrty
    {
        Point p;
        char instrToWalkBack;
        DFSEnrty();
        DFSEnrty(Point tp, char i);
    };
    int width, height;
    bool meetEnd;

    Point start, end, current;
    void setStartEnd();
    std::vector<std::vector<MapEntry>> map;
    
    std::stack<DFSEnrty> DFSstack;

public:
    MapSolver();
    int getCurrentX();
    int getCurrentY();
    void initMap(int width, int height);
    void setMap(std::vector<std::vector<int>> mapFromServer, int width, int height);
    void mergeViewPortIntoMap(std::vector<std::vector<int>> mapFromServer, int midX, int midY, int width, int height);
    std::string solve();
    std::string solveByDFS(bool firstRun);
    bool hasMeetEnd();
    void printMap();
};
