#!/bin/bash
cecho(){
    BLUE="\033[0;34m"
    GREEN="\033[0;32m"
    NC="\033[0m" # No Color

    printf "${!1}${2} ${NC}\n"
}

killall python3 2> /dev/null
VAR=$(
    #. /home/toroto008/Documents/ETHZ/InfoSecLab/Module2/TLS/venv/bin/activate > /dev/null  # activate virtualenv
    # tool from /opt/bin/ which requires virtualenv
    python3 psk_server.py 1>&2
) & sleep 1 && VAR2=$(
    #. /home/toroto008/Documents/ETHZ/InfoSecLab/Module2/TLS/venv/bin/activate > /dev/null  # activate virtualenv
    # tool from /opt/bin/ which requires virtualenv
    python3 psk_client.py 2>&1 && killall python3
)
cecho "GREEN" "$VAR2"