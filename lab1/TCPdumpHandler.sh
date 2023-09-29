#!/bin/bash

timeout 5m sudo tcpdump -w ${GETFLAG_WORKSPACE_FOLDER}/TCP_dump_file.pcap -ni any -Xxnv udp and port 10495

exit 0