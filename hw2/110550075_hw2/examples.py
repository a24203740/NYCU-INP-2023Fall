#!/usr/bin/env python3
from pwn import *

SERVER = "localhost"
PORT = 8080


def get_connection():
    conn = remote(SERVER, PORT, "ipv4", "tcp")
    conn.recvuntil(b"Welcome to the Chat server.")
    conn.recvuntil(b"*********************************\n")
    return conn


def command(conn, command, expected_output=None, prompt=True):
    if prompt:
        conn.recvuntil(b"% ")

    # For testcase, command can't be empty
    if len(command) > 0:
        conn.sendline(command)
        # print in yellow
        print(f"\033[33mCommand: {command.decode()}\033[0m")
    else:
        print(f"\033[33mCommand: <empty>\033[0m")

    if expected_output:
        for output in expected_output:
            line = conn.recvline().strip()
            print(f"\033[34mResult: {line}\033[0m")
            assert line == output, f"\nExpected: {output}\nActual: {line}"


def example1():
    ta1 = get_connection()
    ta3 = get_connection()

    command(ta1, b"register", [b"Usage: register <username> <password>"])
    command(ta1, b"register ta1 420420", [b"Register successfully."])
    command(ta1, b"register ta1 420420", [b"Username is already used."])
    command(ta1, b"login", [b"Usage: login <username> <password>"])
    command(ta1, b"login ta1", [b"Usage: login <username> <password>"])
    command(ta1, b"login ta1 000000", [b"Login failed."])
    command(ta1, b"login Tom 420420", [b"Login failed."])
    command(ta1, b"login ta1 420420", [b"Welcome, ta1."])
    command(ta1, b"whoami", [b"ta1"])
    command(ta1, b"login ta1 420420", [b"Please logout first."])
    command(ta1, b"logout", [b"Bye, ta1."])
    command(ta1, b"logout", [b"Please login first."])
    command(ta1, b"register ta2 ta2", [b"Register successfully."])

    command(ta3, b"register ta3 ta3", [b"Register successfully."])
    command(ta3, b"login ta3 ta3", [b"Welcome, ta3."])
    command(ta3, b"list-user", [b"ta1 offline", b"ta2 offline", b"ta3 online"])

    command(ta1, b"exit")

    command(ta3, b"set-status happyhappy", [b"set-status failed"])
    command(ta3, b"set-status busy", [b"ta3 busy"])
    command(ta3, b"list-user", [b"ta1 offline", b"ta2 offline", b"ta3 busy"])
    command(ta3, b"exit", [b"Bye, ta3."])

    ta1.close()
    ta3.close()


def example2():
    ta1 = get_connection()
    ta2 = get_connection()

    command(ta1, b"login ta1 420420", [b"Welcome, ta1."])
    command(ta1, b"enter-chat-room", [b"Usage: enter-chat-room <number>"])
    command(ta1, b"enter-chat-room 1010", [b"Number 1010 is not valid."])
    command(
        ta1,
        b"enter-chat-room 20",
        [b"Welcome to the public chat room.", b"Room number: 20", b"Owner: ta1"],
    )

    command(ta1, b"/exit-chat-room", prompt=False)

    command(
        ta1,
        b"enter-chat-room 30",
        [b"Welcome to the public chat room.", b"Room number: 30", b"Owner: ta1"],
    )

    command(ta1, b"hello, i am ta1.", [b"[ta1]: *****, i am ta1."], prompt=False)
    command(
        ta1,
        b"i am waiting for everyone.",
        [b"[ta1]: i am waiting for everyone."],
        prompt=False,
    )

    command(ta2, b"login ta2 ta2", [b"Welcome, ta2."])
    command(ta2, b"list-chat-room", [b"ta1 20", b"ta1 30"])
    command(ta2, b"close-chat-room", [b"Usage: close-chat-room <number>"])
    command(ta2, b"close-chat-room 30", [b"Only the owner can close this chat room."])

    command(
        ta2,
        b"enter-chat-room 30",
        [
            b"Welcome to the public chat room.",
            b"Room number: 30",
            b"Owner: ta1",
            b"[ta1]: *****, i am ta1.",
            b"[ta1]: i am waiting for everyone.",
        ],
    )
    command(ta1, b"", [b"ta2 had enter the chat room."], prompt=False)

    command(ta2, b"merry christmas!", [b"[ta2]: merry christmas!"], prompt=False)
    command(ta1, b"", [b"[ta2]: merry christmas!"], prompt=False)

    command(ta1, b"exit", [b"[ta1]: exit"], prompt=False)
    command(ta2, b"", [b"[ta1]: exit"], prompt=False)

    command(ta2, b"/close-chat-room 30", [b"Error: Unknown command"], prompt=False)

    command(ta1, b"/exit-chat-room", prompt=False)
    command(ta2, b"", [b"ta1 had left the chat room."], prompt=False)

    command(ta1, b"list-chat-room", [b"ta1 20", b"ta1 30"])
    command(ta1, b"close-chat-room 35", [b"Chat room 35 does not exist."])

    command(ta1, b"close-chat-room 20", [b"Chat room 20 was closed."])
    command(ta1, b"list-chat-room", [b"ta1 30"])

    command(ta1, b"close-chat-room 30", [b"Chat room 30 was closed."])
    command(ta2, b"", [b"Chat room 30 was closed."], prompt=False)

    command(ta1, b"list-chat-room")
    command(ta1, b"exit", [b"Bye, ta1."])

    command(ta2, b"close-chat-room 30", [b"Chat room 30 does not exist."])
    command(ta2, b"hello", [b"Error: Unknown command"])
    command(ta2, b"exit", [b"Bye, ta2."])

    ta1.close()
    ta2.close()


def example3():
    bob = get_connection()
    tom = get_connection()
    nobody = get_connection()

    command(bob, b"register Bob 55555", [b"Register successfully."])
    command(bob, b"login Bob 55555", [b"Welcome, Bob."])
    command(
        bob,
        b"enter-chat-room 25",
        [
            b"Welcome to the public chat room.",
            b"Room number: 25",
            b"Owner: Bob",
        ],
    )

    command(bob, b"I will win !!!", [b"[Bob]: I will win !!!"], prompt=False)
    command(bob, b"/delete-pin", [b"No pin message in chat room 25"], prompt=False)
    command(
        bob,
        b"/pin You are the challenger.",
        [b"Pin -> [Bob]: You are the challenger."],
        prompt=False,
    )
    command(bob, b"/exit-chat-room", prompt=False)

    command(tom, b"register Tom 22222", [b"Register successfully."])
    command(tom, b"login Tom 22222", [b"Welcome, Tom."])
    command(
        tom,
        b"enter-chat-room 25",
        [
            b"Welcome to the public chat room.",
            b"Room number: 25",
            b"Owner: Bob",
            b"[Bob]: I will win !!!",
            b"Pin -> [Bob]: You are the challenger.",
        ],
    )

    command(
        bob,
        b"enter-chat-room 25",
        [
            b"Welcome to the public chat room.",
            b"Room number: 25",
            b"Owner: Bob",
            b"[Bob]: I will win !!!",
            b"Pin -> [Bob]: You are the challenger.",
        ],
    )
    command(tom, b"", [b"Bob had enter the chat room."], prompt=False)

    command(tom, b"hello", [b"[Tom]: *****"], prompt=False)
    command(bob, b"", [b"[Tom]: *****"], prompt=False)

    command(bob, b"?", [b"[Bob]: ?"], prompt=False)
    command(tom, b"", [b"[Bob]: ?"], prompt=False)

    command(bob, b"domain expansion.", [b"[Bob]: ****************."], prompt=False)
    command(tom, b"", [b"[Bob]: ****************."], prompt=False)

    command(tom, b"What?", [b"[Tom]: What?"], prompt=False)
    command(bob, b"", [b"[Tom]: What?"], prompt=False)

    command(
        bob, b"domain expansion!!!???", [b"[Bob]: ****************!!!???"], prompt=False
    )
    command(tom, b"", [b"[Bob]: ****************!!!???"], prompt=False)

    command(
        tom,
        b"/pin You are an ordinary person.",
        [b"Pin -> [Tom]: You are an ordinary person."],
        prompt=False,
    )
    command(bob, b"", [b"Pin -> [Tom]: You are an ordinary person."], prompt=False)

    command(bob, b"/exit-chat-room", prompt=False)
    command(tom, b"", [b"Bob had left the chat room."], prompt=False)

    command(bob, b"set-status offline", [b"Bob offline"])
    command(
        bob,
        b"enter-chat-room 25",
        [
            b"Welcome to the public chat room.",
            b"Room number: 25",
            b"Owner: Bob",
            b"[Bob]: I will win !!!",
            b"[Tom]: *****",
            b"[Bob]: ?",
            b"[Bob]: ****************.",
            b"[Tom]: What?",
            b"[Bob]: ****************!!!???",
            b"Pin -> [Tom]: You are an ordinary person.",
        ],
    )
    command(tom, b"", [b"Bob had enter the chat room."], prompt=False)

    command(bob, b"I'm sorry.", [b"[Bob]: I'm sorry."], prompt=False)
    command(tom, b"", [b"[Bob]: I'm sorry."], prompt=False)

    command(
        bob,
        b"I couldn't bring out the best in you.",
        [b"[Bob]: I couldn't bring out the best in you."],
        prompt=False,
    )
    command(tom, b"", [b"[Bob]: I couldn't bring out the best in you."], prompt=False)

    command(tom, b"/list-user", [b"Bob offline", b"Tom online"], prompt=False)

    command(bob, b"/delete-pin", prompt=False)

    command(tom, b"I won't forget you.", [b"[Tom]: I won't forget you."], prompt=False)
    command(bob, b"", [b"[Tom]: I won't forget you."], prompt=False)

    command(tom, b"You can't beat me.", [b"[Tom]: You can't beat me."], prompt=False)
    command(bob, b"", [b"[Tom]: You can't beat me."], prompt=False)

    command(tom, b"Cheer up !!!", [b"[Tom]: Cheer up !!!"], prompt=False)
    command(bob, b"", [b"[Tom]: Cheer up !!!"], prompt=False)

    command(bob, b"/exit-chat-room", prompt=False)
    command(tom, b"", [b"Bob had left the chat room."], prompt=False)

    command(tom, b"Bye Bye.", [b"[Tom]: Bye Bye."], prompt=False)
    command(tom, b"Who else?", [b"[Tom]: Who else?"], prompt=False)

    command(nobody, b"register nobody 11111", [b"Register successfully."])
    command(nobody, b"login nobody 11111", [b"Welcome, nobody."])
    command(
        nobody,
        b"enter-chat-room 25",
        [
            b"Welcome to the public chat room.",
            b"Room number: 25",
            b"Owner: Bob",
            b"[Bob]: ****************.",
            b"[Tom]: What?",
            b"[Bob]: ****************!!!???",
            b"[Bob]: I'm sorry.",
            b"[Bob]: I couldn't bring out the best in you.",
            b"[Tom]: I won't forget you.",
            b"[Tom]: You can't beat me.",
            b"[Tom]: Cheer up !!!",
            b"[Tom]: Bye Bye.",
            b"[Tom]: Who else?",
        ],
    )
    command(tom, b"", [b"nobody had enter the chat room."], prompt=False)

    command(nobody, b"/exit-chat-room", prompt=False)
    command(tom, b"", [b"nobody had left the chat room."], prompt=False)

    command(tom, b"/exit-chat-room", prompt=False)

    # For me to play
    command(bob, b"exit", [b"Bye, Bob."])
    command(tom, b"exit", [b"Bye, Tom."])
    command(nobody, b"exit", [b"Bye, nobody."])

    bob.close()
    tom.close()
    nobody.close()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])

    server = process(["./hw2_chat_server", str(PORT)])

    example1()
    example2()
    example3()

    server.interactive()
    server.close()
