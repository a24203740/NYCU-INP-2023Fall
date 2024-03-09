#!/bin/bash

mkdir hidden1
touch ./hidden1/client1.txt

# Start a new Tmux session named 'multi_terminal'
tmux new-session -d -s hidden1

tmux split-window -h

# Send commands to the panes (adjust commands as needed)
tmux send-keys -t 0 'nc localhost 8888 1>./hidden1/client1.txt' C-m

tmux send-keys -t 0 'login abc123' C-m
sleep 0.5
tmux send-keys -t 0 'register abc123 123@123' C-m
sleep 0.5
tmux send-keys -t 0 'login abc123 123@123' C-m
sleep 0.5
tmux send-keys -t 0 'enter-chat-room 12' C-m
sleep 0.5
tmux send-keys -t 0 'starburst stream!!!' C-m
sleep 0.5

tmux send-keys -t 0 '/pin starburst stream!!!' C-m
sleep 0.5
tmux send-keys -t 0 '/pin starburst stream!!!' C-m
sleep 0.5
tmux send-keys -t 0 '/list-user' C-m
sleep 0.5
tmux send-keys -t 0 'exit' C-m
sleep 0.5


tmux send-keys -t 1 'diff ./hidden1/client1_ans.txt  ./hidden1/client1.txt' C-m

# Attach to the Tmux session to view the created panes
tmux attach-session -t hidden1
