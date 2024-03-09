#!/bin/bash

mkdir example3
touch ./example3/client1.txt
touch ./example3/client2.txt
touch ./example3/client3.txt

# Start a new Tmux session named 'multi_terminal'
tmux new-session -d -s example3

# Split the window into multiple panes
tmux split-window -h
tmux split-window -h
tmux split-window -h

# Send commands to the panes (adjust commands as needed)
tmux send-keys -t 0 'nc localhost 8888 1>./example3/client1.txt' C-m
tmux send-keys -t 1 'nc localhost 8888 1>./example3/client2.txt' C-m
tmux send-keys -t 2 'nc localhost 8888 1>./example3/client3.txt' C-m

tmux send-keys -t 0 'register Bob 55555' C-m
sleep 0.5
tmux send-keys -t 0 'login Bob 55555' C-m
sleep 0.5
tmux send-keys -t 0 'enter-chat-room 25' C-m
sleep 0.5
tmux send-keys -t 0 'I will win !!!' C-m
sleep 0.5
tmux send-keys -t 0 '/delete-pin' C-m
sleep 0.5

tmux send-keys -t 0 '/pin You are the challenger.' C-m
sleep 0.5
tmux send-keys -t 0 '/exit-chat-room' C-m
sleep 0.5
tmux send-keys -t 1 'register Tom 22222' C-m
sleep 0.5
tmux send-keys -t 1 'login Tom 22222' C-m
sleep 0.5
tmux send-keys -t 1 'enter-chat-room 25' C-m
sleep 0.5

tmux send-keys -t 0 'enter-chat-room 25' C-m
sleep 0.5
tmux send-keys -t 1 'hello' C-m
sleep 0.5
tmux send-keys -t 0 '?' C-m
sleep 0.5
tmux send-keys -t 0 'domain expansion.' C-m
sleep 0.5
tmux send-keys -t 1 'What?' C-m
sleep 0.5

tmux send-keys -t 0 'domain expansion!!!???' C-m
sleep 0.5
tmux send-keys -t 1 '/pin You are an ordinary person.' C-m
sleep 0.5
tmux send-keys -t 0 '/exit-chat-room' C-m
sleep 0.5
tmux send-keys -t 0 'set-status offline' C-m
sleep 0.5
tmux send-keys -t 0 'enter-chat-room 25' C-m
sleep 0.5

tmux send-keys -t 0 "I'm sorry." C-m
sleep 0.5
tmux send-keys -t 0 "I couldn't bring out the best in you." C-m
sleep 0.5
tmux send-keys -t 1 '/list-user' C-m
sleep 0.5
tmux send-keys -t 0 '/delete-pin' C-m
sleep 0.5
tmux send-keys -t 1 "I won't forget you." C-m
sleep 0.5

tmux send-keys -t 1 "You can't beat me." C-m
sleep 0.5
tmux send-keys -t 1 "Cheer up !!!" C-m
sleep 0.5
tmux send-keys -t 0 '/exit-chat-room' C-m
sleep 0.5
tmux send-keys -t 1 'Bye Bye.' C-m
sleep 0.5
tmux send-keys -t 1 'Who else?' C-m
sleep 0.5

tmux send-keys -t 2 'register nobody 11111' C-m
sleep 0.5
tmux send-keys -t 2 'login nobody 11111' C-m
sleep 0.5
tmux send-keys -t 2 'enter-chat-room 25' C-m
sleep 0.5
tmux send-keys -t 2 '/exit-chat-room' C-m
sleep 0.5
tmux send-keys -t 1 '/exit-chat-room' C-m
sleep 0.5

tmux send-keys -t 3 'diff ./example3/client1_ans.txt  ./example3/client1.txt' C-m
tmux send-keys -t 3 'diff ./example3/client2_ans.txt  ./example3/client2.txt' C-m
tmux send-keys -t 3 'diff ./example3/client3_ans.txt  ./example3/client3.txt' C-m

# Attach to the Tmux session to view the created panes
tmux attach-session -t example3
