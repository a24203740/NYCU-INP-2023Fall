#!/bin/bash

# if no input argument is provided
if [ "${1}" == "" ] || [ "${2}" == "" ] ; then
    echo "Usage: getFlag <id> <sudo password>"
    exit -1
elif [ $# -ne 2 ]; then
    echo "Too many/few args!"
    exit -1
fi

RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SUDO_PASSWD=${2}
GETFLAG_WORKSPACE_FOLDER="$(pwd)"
GETFLAG_TMP_FOLDER="${GETFLAG_WORKSPACE_FOLDER}/intermidateFileFolderOfGetFlagScript"
SERVER_ADDRESS="inp.zoolab.org"
# SERVER_ADDRESS="127.0.0.1"

export GETFLAG_WORKSPACE_FOLDER
export GETFLAG_TMP_FOLDER
export SUDO_PASSWD
export RED
export CYAN
export NC
export SERVER_ADDRESS

if [ -d ${GETFLAG_TMP_FOLDER} ]; then
	echo -e "${RED}${GETFLAG_TMP_FOLDER} exists, remove it.${NC}"
    rm -rf ${GETFLAG_TMP_FOLDER}
fi

mkdir ${GETFLAG_TMP_FOLDER}

echo -n hello ${1} > ${GETFLAG_TMP_FOLDER}/ncHelloInput

echo -e "${CYAN}run ncHandler.sh${NC}"
echo -e "${CYAN}===============${NC}"

bash ${GETFLAG_WORKSPACE_FOLDER}/ncHandler.sh

echo -e "${CYAN}===============${NC}"

echo -e "${CYAN}Got PCAP file store at ${GETFLAG_WORKSPACE_FOLDER}/TCP_dump_file.pcap${NC}"

./PCAPparser ${GETFLAG_WORKSPACE_FOLDER}/TCP_dump_file.pcap

echo -e "${CYAN}Get Flag: $(cat ./FlagOutput | cut -c 7-)${NC}"

echo -e "${CYAN}sending verfy to server${NC}"
timeout 1 nc -u ${SERVER_ADDRESS} 10495 < ./FlagOutput | tee ${GETFLAG_WORKSPACE_FOLDER}/ncVerfyOutput

echo -e "${CYAN}script done${NC}"

exit 0
