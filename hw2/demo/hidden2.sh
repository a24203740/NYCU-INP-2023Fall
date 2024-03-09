#!/bin/bash

mkdir hidden2
touch ./hidden2/client1.txt
touch ./hidden2/client2.txt
touch ./hidden2/client3.txt

# Start a new Tmux session named 'multi_terminal'
tmux new-session -d -s hidden2

# Split the window into multiple panes
tmux split-window -h
tmux split-window -h
tmux split-window -h

# Send commands to the panes (adjust commands as needed)
tmux send-keys -t 0 'nc localhost 8888 1>./hidden2/client1.txt' C-m
tmux send-keys -t 1 'nc localhost 8888 1>./hidden2/client2.txt' C-m
tmux send-keys -t 2 'nc localhost 8888 1>./hidden2/client3.txt' C-m

tmux send-keys -t 0 'register SpongeBob wonderfulworld' C-m
sleep 0.5
tmux send-keys -t 0 'login SpongeBob wonderfulworld' C-m
sleep 0.5
tmux send-keys -t 1 'register Squidward UnappreciatedArtist' C-m
sleep 0.5
tmux send-keys -t 0 'list-user' C-m
sleep 0.5
tmux send-keys -t 0 'enter-chat-room 10' C-m
sleep 0.5

tmux send-keys -t 0 "it's a beautiful day" C-m
sleep 0.5
tmux send-keys -t 0 '/exit-chat-room' C-m
sleep 0.5
tmux send-keys -t 0 'close-chat-room 10' C-m
sleep 0.5
tmux send-keys -t 1 'login Squidward UnappreciatedArtist' C-m
sleep 0.5
tmux send-keys -t 1 'set-status offline' C-m
sleep 0.5

tmux send-keys -t 0 'set-status busy' C-m
sleep 0.5
tmux send-keys -t 1 'enter-chat-room 10' C-m
sleep 0.5
tmux send-keys -t 0 'enter-chat-room 10' C-m
sleep 0.5
tmux send-keys -t 1 '(sighs) I hate my job' C-m
sleep 0.5
tmux send-keys -t 2 'register Mr.Krabs ilovemoney' C-m
sleep 0.5

tmux send-keys -t 2 'login Mr.Krabs ilovemoney' C-m
sleep 0.5
tmux send-keys -t 2 'enter-chat-room 10' C-m
sleep 0.5
tmux send-keys -t 2 'Squidward, your work attitude needs to change.' C-m
sleep 0.5
tmux send-keys -t 2 '/exit-chat-room' C-m
sleep 0.5
tmux send-keys -t 2 'close-chat-room 10' C-m
sleep 0.5

tmux send-keys -t 2 'list-user' C-m
sleep 0.5
tmux send-keys -t 0 '/exit-chat-room' C-m
sleep 0.5
tmux send-keys -t 0 'logout' C-m
sleep 0.5
tmux send-keys -t 2 'list-user' C-m
sleep 0.5
tmux send-keys -t 2 'enter-chat-room 10' C-m
sleep 0.5

tmux send-keys -t 1 '/exit-chat-room' C-m
sleep 0.5
tmux send-keys -t 1 'close-chat-room 10' C-m
sleep 0.5

tmux send-keys -t 3 'diff ./hidden2/client1_ans.txt  ./hidden2/client1.txt' C-m
tmux send-keys -t 3 'diff ./hidden2/client2_ans.txt  ./hidden2/client2.txt' C-m
tmux send-keys -t 3 'diff ./hidden2/client3_ans.txt  ./hidden2/client3.txt' C-m

# Attach to the Tmux session to view the created panes
tmux attach-session -t hidden2

