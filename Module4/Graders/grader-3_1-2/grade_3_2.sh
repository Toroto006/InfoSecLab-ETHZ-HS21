#!/bin/bash
#$1 : solution script path
#$2 : number of test cases

PATH_TO_VM_IMAGE=VM_Task3_1_2.ova
USERNAME=sgx
SCP_PORT=3022
SSH_PORT=3022
TASK_FOLDER="/home/sgx/isl/t2"
OP_FOLDER="/home/sgx/isl/t2/output"
SAMPLES_FOLDER="/home/sgx/isl/t2/samples"
TIME=60
VM_NAME=VM_Task3-1-2_Grade

rm -f oput_*

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
echo 'copied solution solution python file to VM'
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 rm -rf $OP_FOLDER
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 mkdir $OP_FOLDER
echo $1
rm -f executions.txt
touch executions.txt
COUNT=0
STR="success"
echo "testcase","no_executions","status" >> executions.txt

NO_TESTS=5
if [ ! -z  "$2" ]; then
    NO_TESTS=$2
fi

for (( i=1;i<=$NO_TESTS;i++ ))
do
    ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 rm -f $TASK_FOLDER/password.txt
    scp -P $SCP_PORT -i ./id_rsa ./samples/$i/password.txt $USERNAME@127.0.0.1:$TASK_FOLDER
    ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 timeout $TIME python3 $TASK_FOLDER/submit_3_2.py $i
    COUNT=1
    OP=$OP_FOLDER/oput_$i
    if ! scp -P $SCP_PORT -i ./id_rsa $USERNAME@127.0.0.1:$OP ./; then
        echo "Testcase $i : Output file not created on first execution: running the script again "
        ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 timeout $TIME python3 $TASK_FOLDER/submit_3_2.py $i
        COUNT=2
        if ! scp -P $SCP_PORT -i ./id_rsa $USERNAME@127.0.0.1:$OP ./; then
            echo "Testcase $i: Output file not created on second execution: running the script again "
            ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 timeout $TIME python3 $TASK_FOLDER/submit_3_2.py $i
            COUNT=3
            if ! scp -P $SCP_PORT -i ./id_rsa $USERNAME@127.0.0.1:$OP ./; then
                echo "Testcase $i : Output file not created on third execution: stopping now "
                echo "Failed for: " $i
                STR="failed"
            fi
        fi
    fi   
    echo $i,$COUNT,$STR >> executions.txt

done




