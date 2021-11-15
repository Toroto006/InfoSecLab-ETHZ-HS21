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

if ! VBoxManage list vms | grep $VM_NAME; then  
    VBoxManage import $PATH_TO_VM_IMAGE --vsys 0 --vmname $VM_NAME
else 
    echo "VM by name $VM_NAME already exists. Not importing new VM. To import a fresh VM delete the existsing VM first"
fi

if ! VBoxManage list runningvms | grep $VM_NAME; then 
    VBoxManage startvm "$VM_NAME" --type headless
else 
    echo "VM by name $VM_NAME is already running. Not restarting it."
fi


sleep 5
scp -P $SCP_PORT -i ./id_rsa $1 $USERNAME@127.0.0.1:$TASK_FOLDER
scp -P $SCP_PORT -i ./id_rsa public_test_set.csv $USERNAME@127.0.0.1:$TASK_FOLDER/test
echo 'copied solution c file and new csv to VM'
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 rm -f $TASK_FOLDER/a.out
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 $TASK_FOLDER/build.sh
echo "built binary"
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 chmod +x $TEST_FOLDER/*.sh
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 rm -rf $TEST_FOLDER/traces
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 mkdir $TEST_FOLDER/traces
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 python3 $TEST_FOLDER/run_tracer.py
echo 'ran tracer'
if scp -P $SCP_PORT -i ./id_rsa $USERNAME@localhost:$TEST_FOLDER/forked ./ >&/dev/null;
      then echo "found forked"; 
fi

if ! scp -P $SCP_PORT -i ./id_rsa $USERNAME@localhost:$TEST_FOLDER/functionality.csv .; then 
      echo "functionality.csv not found"
fi
echo 'run diff now'

ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 python3 $TEST_FOLDER/diff_traces.py

if ! scp -P $SCP_PORT -i ./id_rsa $USERNAME@localhost:$TEST_FOLDER/diff_traces.csv .; then
      echo "diff_traces.csv not found"
fi

python3 check_outputs.py
cat grade-3-3-11-111-111