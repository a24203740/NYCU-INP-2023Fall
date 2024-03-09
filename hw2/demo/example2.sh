#!/bin/bash

mkdir example2
touch ./example2/client1.txt
touch ./example2/client2.txt

# Start a new Tmux session named 'multi_terminal'
tmux new-session -d -s example2

# Split the window into multiple panes
tmux split-window -h
tmux split-window -h

# Send commands to the panes (adjust commands as needed)
tmux send-keys -t 0 'nc localhost 8888 1>./example2/client1.txt' C-m
tmux send-keys -t 1 'nc localhost 8888 1>./example2/client2.txt' C-m

tmux send-keys -t 0 'register ta1 420420' C-m
sleep 0.5
tmux send-keys -t 1 'register ta2 ta2' C-m
sleep 0.5

tmux send-keys -t 0 'login ta1 420420' C-m
sleep 0.5
tmux send-keys -t 0 'enter-chat-room' C-m
sleep 0.5
tmux send-keys -t 0 'enter-chat-room 1010' C-m
sleep 0.5
tmux send-keys -t 0 'enter-chat-room 20' C-m
sleep 0.5
tmux send-keys -t 0 '/exit-chat-room' C-m
sleep 0.5

tmux send-keys -t 0 'enter-chat-room 30' C-m
sleep 0.5
tmux send-keys -t 0 'hello, i am ta1' C-m
sleep 0.5
tmux send-keys -t 0 'i am waiting for everyone.' C-m
sleep 0.5
tmux send-keys -t 1 'login ta2 ta2' C-m
sleep 0.5
tmux send-keys -t 1 'list-chat-room' C-m
sleep 0.5

tmux send-keys -t 1 'close-chat-room' C-m
sleep 0.5
tmux send-keys -t 1 'close-chat-room 30' C-m
sleep 0.5
tmux send-keys -t 1 'enter-chat-room 30' C-m
sleep 0.5
tmux send-keys -t 1 'merry christmas!' C-m
sleep 0.5
tmux send-keys -t 0 'exit' C-m
sleep 0.5

tmux send-keys -t 1 '/close-chat-room 30' C-m
sleep 0.5
tmux send-keys -t 0 '/exit-chat-room' C-m
sleep 0.5
tmux send-keys -t 0 'list-chat-room' C-m
sleep 0.5
tmux send-keys -t 0 'close-chat-room 35' C-m
sleep 0.5
tmux send-keys -t 0 'close-chat-room 20' C-m
sleep 0.5

tmux send-keys -t 0 'list-chat-room' C-m
sleep 0.5
tmux send-keys -t 0 'close-chat-room 30' C-m
sleep 0.5
tmux send-keys -t 0 'list-chat-room' C-m
sleep 0.5
tmux send-keys -t 0 'exit' C-m
sleep 0.5
tmux send-keys -t 1 'close-chat-room 30' C-m
sleep 0.5

tmux send-keys -t 1 'hello' C-m
sleep 0.5
tmux send-keys -t 1 'exit' C-m
sleep 0.5

tmux send-keys -t 2 'diff ./example2/client1_ans.txt  ./example2/client1.txt' C-m
tmux send-keys -t 2 'diff ./example2/client2_ans.txt  ./example2/client2.txt' C-m

# Attach to the Tmux session to view the created panes
tmux attach-session -t example2
