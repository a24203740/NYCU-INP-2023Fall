#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

mkdir example1
touch ./example1/client1.txt
touch ./example1/client2.txt

# Start a new Tmux session named 'multi_terminal'
tmux new-session -d -s example1

# Split the window into multiple panes
tmux split-window -h
tmux split-window -v

# Send commands to the panes (adjust commands as needed)
tmux send-keys -t 0 'nc localhost 8888 1>./example1/client1.txt' C-m
sleep 3
tmux send-keys -t 1 'nc localhost 8888 1>./example1/client2.txt' C-m
sleep 1

tmux send-keys -t 0 'register' C-m
sleep 0.5
tmux send-keys -t 0 'register ta1 420420' C-m
sleep 0.5
tmux send-keys -t 0 'register ta1 420420' C-m
sleep 0.5
tmux send-keys -t 0 'login' C-m
sleep 0.5
tmux send-keys -t 0 'login ta1' C-m
sleep 0.5

tmux send-keys -t 0 'login ta1 000000' C-m
sleep 0.5
tmux send-keys -t 0 'login Tom 420420' C-m
sleep 0.5
tmux send-keys -t 0 'login ta1 420420' C-m
sleep 0.5
tmux send-keys -t 0 'whoami' C-m
sleep 0.5
tmux send-keys -t 0 'login ta1 420420' C-m
sleep 0.5

tmux send-keys -t 0 'logout' C-m
sleep 0.5
tmux send-keys -t 0 'logout' C-m
sleep 0.5
tmux send-keys -t 0 'register ta2 777777' C-m
sleep 0.5
tmux send-keys -t 1 'register ta3 ta3' C-m
sleep 0.5
tmux send-keys -t 1 'login ta3 ta3' C-m
sleep 0.5

tmux send-keys -t 1 'list-user' C-m
sleep 0.5
tmux send-keys -t 0 'exit' C-m
sleep 0.5
tmux send-keys -t 1 'set-status happyhappy' C-m
sleep 0.5
tmux send-keys -t 1 'set-status busy' C-m
sleep 0.5
tmux send-keys -t 1 'list-user' C-m
sleep 0.5

tmux send-keys -t 1 'exit' C-m
sleep 0.5

# tmux send-keys -t 2 "echo '============== Example1 =============='" C-m
tmux send-keys -t 2 'diff ./example1/client1_ans.txt  ./example1/client1.txt' C-m
tmux send-keys -t 2 'diff ./example1/client2_ans.txt  ./example1/client2.txt' C-m


# Attach to the Tmux session to view the created panes
tmux attach-session -t example1



