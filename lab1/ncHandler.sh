#!/bin/bash

for (( i=1; i<=10; i=i+1 ))
do
    echo -e "${CYAN}sending hello to server${NC}"
    
    timeout 1 nc -u ${SERVER_ADDRESS} 10495 < ${GETFLAG_TMP_FOLDER}/ncHelloInput | tee ${GETFLAG_TMP_FOLDER}/ncChalsInput

    if [ "$(cat ${GETFLAG_TMP_FOLDER}/ncChalsInput | grep OK)" != "" ]; then
        break
    fi
    echo -e "${CYAN}hello failed, wait for 5 second and retry${NC}"
    sleep 5
done

echo -e "${CYAN}hello success${NC}"

CHALS_ID=$(cat ${GETFLAG_TMP_FOLDER}/ncChalsInput | cut -c 4-)
echo "chals ${CHALS_ID}" > ${GETFLAG_TMP_FOLDER}/ncChalsInput

# -E:   Indicates to the security policy that the user wishes to preserve their existing environment variables.
# &:    background process
echo ${SUDO_PASSWD} | sudo -E bash ${GETFLAG_WORKSPACE_FOLDER}/TCPdumpHandler.sh &

sleep 5

for (( i=1; i<=10; i=i+1 ))
do
    echo -e "${CYAN}sending chals to server${NC}"
    
    timeout 3 nc -u ${SERVER_ADDRESS} 10495 < ${GETFLAG_TMP_FOLDER}/ncChalsInput > ${GETFLAG_TMP_FOLDER}/ncChalsResponse

    if [ "$(cat ${GETFLAG_TMP_FOLDER}/ncChalsResponse | grep SEQ | head -n 3)" != "" ]; then
        break
    fi
    echo -e "${CYAN}Chals failed, wait for 10 second and retry${NC}"
    sleep 10
done

echo -e "${CYAN}Chals success, Killing tcpdump${NC}"
echo ${SUDO_PASSWD} | sudo kill -SIGINT $(ps -a o pid,comm | tr -s ' ' | grep tcpdump | cut -d ' ' -f 1)

exit 0