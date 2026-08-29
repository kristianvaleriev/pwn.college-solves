#!/bin/bash

CWD=$(pwd)
DOMAIN="hacker@dojo.pwn.college"


move_to_current_challenge() {
    HOSTNAME=$(ssh -i "$CWD/key" $DOMAIN 'echo $HOSTNAME')
    IFS='~' read -ra ARRAY <<< "$HOSTNAME"
    [[ ${ARRAY[0]} = "practice" ]] && unset 'ARRAY[0]'

    for dir in "${ARRAY[@]}"; do 
        mkdir -v "$dir" 2> /dev/null
        cd "$dir"
    done
}


get_challenges() {
    move_to_current_challenge

    scp -i "$CWD/key" "$DOMAIN:/challenge/*" ./
    checksec ./*
}


if [[ $# -eq 0 ]]; then 
    get_challenges
else
    move_to_current_challenge
    echo "now in $(pwd)"
fi

while true; do
    read -p "Input [Solve/'g'et/'m'ove]... " input

    case $input in 
        [Gg]) 
            cd "$CWD"
            get_challenges
        ;;
        [Mm])
            cd "$CWD"
            move_to_current_challenge
            echo "cd to" $(pwd)
        ;;
        *)
            scp -i "$CWD/key"  ./solve*  "$DOMAIN:/home/hacker/"
        ;;

    esac
done
