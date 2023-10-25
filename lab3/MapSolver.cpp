#include "MapSolver.h"

MapSolver::Point::Point() {
    x = 0;
    y = 0;    
}

MapSolver::Point::Point(int _x, int _y) {
    x = _x;
    y = _y;    
}

MapSolver::DFSEnrty::DFSEnrty() {
    p = Point(-1, -1);
    instrToWalkBack = 'X';  
}

MapSolver::DFSEnrty::DFSEnrty(Point tp, char i) {
    p = tp;
    instrToWalkBack = i; 
}

MapSolver::MapSolver() {
    map.clear();
    DFSstack = std::stack<DFSEnrty>();
    width = 0;
    height = 0;
    meetEnd = false;
    start = Point(-1, -1);
    end = Point(-1, -1);
    current = Point(-1, -1);
}

void MapSolver::setMap(std::vector<std::vector<int>> mapFromServer, int width, int height) {
    this->width = width;
    this->height = height;
    map.assign(height, std::vector<MapEntry>(width));
    for (int i = 0; i < height; i++)
    {
        for (int j = 0; j < width; ++j)
        {
            map[i][j].type = mapFromServer[i][j];
            map[i][j].distance = -1;
            map[i][j].prev = Point(-1, -1);
        }
    }
}



std::string MapSolver::solve() {
    
    std::queue<Point> q;

    auto tryOneStep = [this, &q](int x, int y, int prevX, int prevY, int distance) -> void
    {
        this->map[y][x].distance = distance;
        this->map[y][x].prev = Point(prevX, prevY);
        q.push(Point(x, y));
    };

    auto checkPointIsValid = [this](int x, int y) -> bool
    {
        if(x < 0 || x >= this->width || y < 0 || y >= this->height || this->map[y][x].type == WALL || this->map[y][x].distance != -1)
        {
            return false;
        }
        return true;
    };

    auto tryAllPossibleStep = [this, tryOneStep, checkPointIsValid](Point p, MapEntry m) -> void
    {
        int x = p.x;
        int y = p.y;
        int distance = m.distance + 1;
        if(checkPointIsValid(x, y-1))
        {
            tryOneStep(x, y-1, x, y, distance);
        }
        if(checkPointIsValid(x, y+1))
        {
            tryOneStep(x, y+1, x, y, distance);
        }
        if(checkPointIsValid(x-1, y))
        {
            tryOneStep(x-1, y, x, y, distance);
        }
        if(checkPointIsValid(x+1, y))
        {
            tryOneStep(x+1, y, x, y, distance);
        }
    };
    
    //BFS
    setStartEnd();
    
    q.push(start);
    map[start.y][start.x].distance = 0;

    // add some message to check where program died.
    //std::cout << "Start: " << start.x << " " << start.y << std::endl;
    //std::cout << "End: " << end.x << " " << end.y << std::endl;

    while(!q.empty())
    {
        Point p = q.front();
        if(p.x == end.x && p.y == end.y)
        {
            break;
        }
        q.pop();
        tryAllPossibleStep(p, map[p.y][p.x]);
    }
    std::vector<Point> path;

    /*
    // print all map entry
    for (int i = 0; i < height; i++)
    {
        for (int j = 0; j < width; ++j)
        {
            std::cout << "(" << std::setw(2) << std::setfill(' ') << map[i][j].prevX << ", " << std::setw(2) << std::setfill(' ') << map[i][j].prevY << ")";
        }
        std::cout << std::endl;
    }
    */
    Point tpPoint = end;
    while(tpPoint.x != start.x || tpPoint.y != start.y)
    {
        path.push_back(tpPoint);
        //std::cout << "(" << std::setw(2) << std::setfill(' ') << tpPoint.x << ", " << std::setw(2) << std::setfill(' ') << tpPoint.y << ")" << std::endl;
        //std::cout << "whose prev is (" << std::setw(2) << std::setfill(' ') << map[tpPoint.y][tpPoint.x].prevX << ", " << std::setw(2) << std::setfill(' ') << map[tpPoint.y][tpPoint.x].prevY << ")" << std::endl;

        Point tptpPoint = tpPoint;
        tpPoint = map[tptpPoint.y][tptpPoint.x].prev;
    }
    //std::cout << path.size() << std::endl;

    Point tp = start;
    std::string solution;
    while(!path.empty())
    {
        Point cur = path.back();
        path.pop_back();
        int dx = cur.x - tp.x;
        int dy = cur.y - tp.y;
        if(dx == 1)
        {
            solution.push_back('D');
        }
        else if(dx == -1)
        {
            solution.push_back('A');
        }
        else if(dy == 1)
        {
            solution.push_back('S');
        }
        else if(dy == -1)
        {
            solution.push_back('W');
        }
        tp = cur;
    }
    solution.push_back('\n');
    return solution;
}

void MapSolver::setStartEnd() {
    for (int i = 0; i < height; i++)
    {
        for (int j = 0; j < width; ++j)
        {
            if(map[i][j].type == START)
            {
                start = Point(j, i);
            }
            else if(map[i][j].type == END)
            {
                end = Point(j, i);
            }
        }
    }    
}

void MapSolver::initMap(int width, int height) {
    this->width = width;
    this->height = height;
    map.assign(height, std::vector<MapEntry>(width));
    for(int i = 0; i < height; i++)
    {
        for(int j = 0; j < width; j++)
        {
            map[i][j].type = UNKNOWN;
            map[i][j].distance = -1;
            map[i][j].prev = Point(-1, -1);
        }
    }
    current = Point(width / 2, height / 2);
    start = Point(width / 2, height / 2);
}

void MapSolver::mergeViewPortIntoMap(std::vector<std::vector<int>> mapFromServer, int midX, int midY, int width, int height) {
    int viewleft = midX - width / 2;
    int viewtop = midY - height / 2;
    int viewright = midX + width / 2;
    int viewbottom = midY + height / 2;

    //std::cout << "===\n";
    for (int i = viewtop; i <= viewbottom; i++)
    {
        for (int j = viewleft; j <= viewright; j++)
        {
            
            if(map[i][j].type != UNKNOWN)
            {
                if(map[i][j].type != mapFromServer[i - viewtop][j - viewleft])
                {
                    //std::cout << "! ";
                    // std::cerr << "Error: Merge meet failure!" << std::endl;
                }
                else
                {
                    //std::cout << "- ";
                }
                continue;
            }
            map[i][j].type = mapFromServer[i - viewtop][j - viewleft];
            //std::cout << map[i][j].type << " ";
            map[i][j].distance = -1;
            map[i][j].prev = Point(-1, -1);
        }
        //std::cout << std::endl;
    }
    
}



std::string MapSolver::solveByDFS(bool firstRun) {

    std::string currentInstruction="";

    auto tryOneStep = [this](int x, int y, int prevX, int prevY, int distance, char instr) -> void
    {

        this->map[y][x].distance = distance;
        this->map[y][x].prev = Point(prevX, prevY);
        DFSEnrty d; d.p = Point(x, y); d.instrToWalkBack = instr;
        this->DFSstack.push(d);
    };

    auto checkPointIsValid = [this](int x, int y) -> bool
    {
        if(x < 0 || x >= this->width || y < 0 || y >= this->height || this->map[y][x].type == WALL || this->map[y][x].type == VOID  || this->map[y][x].distance != -1)
        {
            return false;
        }
        return true;
    };

    auto tryAllPossibleStep = [this, tryOneStep, checkPointIsValid, &currentInstruction](Point p, MapEntry m) -> bool
    {
        int x = p.x;
        int y = p.y;
        int distance = m.distance + 1;
        if(checkPointIsValid(x+1, y)) // RIGHT
        {
            currentInstruction += "D";
            tryOneStep(x+1, y, x, y, distance, 'A');
            return true;
        }
        if(checkPointIsValid(x, y-1)) // UP
        {
            currentInstruction += "W";
            tryOneStep(x, y-1, x, y, distance, 'S');
            return true;
        }
        if(checkPointIsValid(x-1, y)) // LEFT
        {
            currentInstruction += "A";
            tryOneStep(x-1, y, x, y, distance, 'D');
            return true;
        }
        if(checkPointIsValid(x, y+1)) // DOWN
        {
            currentInstruction += "S";
            tryOneStep(x, y+1, x, y, distance, 'W');
            return true;
        }
        return false;
    };

    if(firstRun)
    {
        DFSstack.push(DFSEnrty(start, 'X'));
        map[start.y][start.x].distance = 0;
    }
    // MAYBE BUG HERE
    while(!DFSstack.empty())
    {
        DFSEnrty cur = DFSstack.top();
        MapEntry curMapEnrty = map[cur.p.y][cur.p.x];

        if(curMapEnrty.type == UNKNOWN)
        {
            //std::cerr << "Meet Unknown, request viewport" << std::endl;
            
            /* remake, as if we never push UNKNOWN point */
            map[cur.p.y][cur.p.x].distance = -1;
            map[cur.p.y][cur.p.x].prev = Point(-1, -1);
            DFSstack.pop();
            currentInstruction.pop_back();

            return currentInstruction;
        }
        
        current = cur.p;
        if(curMapEnrty.type == END)
        {
            meetEnd = true;
            return currentInstruction;
        }
        bool hasWay = tryAllPossibleStep(cur.p, curMapEnrty);
        if(!hasWay)
        {
            currentInstruction += cur.instrToWalkBack;
            DFSstack.pop();
        }

    }
    return currentInstruction;
}

int MapSolver::getCurrentX() {
    return current.x;    
}

int MapSolver::getCurrentY() {
    return current.y;    
}


bool MapSolver::hasMeetEnd() {
    return meetEnd;    
}

void MapSolver::printMap() {
    for(int r = 0; r < height; r++)
    {
        for(int c = 0; c < width; c++)
        {
            if(map[r][c].type == WALL)
            {
                std::cout << "#";
            }
            else if(map[r][c].type == PATH)
            {
                std::cout << ".";
            }
            else if(map[r][c].type == START)
            {
                std::cout << "*";
            }
            else if(map[r][c].type == END)
            {
                std::cout << "E";
            }            
            else if(map[r][c].type == UNKNOWN)
            {
                std::cout << "";
            }
            else if(map[r][c].type == PATH)
            {
                std::cout << "-";
            }
        }
        std::cout << std::endl;
    }    
}
