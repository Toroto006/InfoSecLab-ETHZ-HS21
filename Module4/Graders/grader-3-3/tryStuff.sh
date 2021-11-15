#!/bin/bash
#$1: path to the solution c file
PATH_TO_VM_IMAGE=VM_Task3_3.ova
USERNAME=sgx
SCP_PORT=3022
SSH_PORT=3022
TASK_FOLDER="/home/sgx/isl/t3_3"
TEST_FOLDER="/home/sgx/isl/t3_3/test"
VM_NAME=VM_Task3_Grade
rm -f forked

scp -P $SCP_PORT -i ./id_rsa $1 $USERNAME@127.0.0.1:$TASK_FOLDER
echo 'copied solution solution c file to VM'
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 rm -f $TASK_FOLDER/a.out
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 $TASK_FOLDER/build.sh
echo "built binary"
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 rm -rf $TEST_FOLDER/traces
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 mkdir $TEST_FOLDER/traces
#magic,magic,magicbeans,wholetmein,77
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 'echo \$\$\$\$\$magicbeans\$\$\$\$\$ > /home/sgx/isl/t3_3/password.txt'
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 "cd $TEST_FOLDER && ./run_single.sh magic magic_magicbeans"
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 'echo \$\$\$\$\$wholetmein\$\$\$\$\$ > /home/sgx/isl/t3_3/password.txt'
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 "cd $TEST_FOLDER && ./run_single.sh magic magic_wholetmein"

#ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 python3 $TEST_FOLDER/diff_traces.py

#ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 "cd $TASK_FOLDER && cat ./a.out | base64 -e" 
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 