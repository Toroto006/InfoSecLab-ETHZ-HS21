#!/bin/bash
#$1 : solution script path
#$2 : number of test cases

PATH_TO_VM_IMAGE=VM_Task3_1_2.ova
USERNAME=sgx
SCP_PORT=3022
SSH_PORT=3022
TASK_FOLDER="/home/sgx/isl/t1"
OP_FOLDER="/home/sgx/isl/t1/output"
SAMPLES_FOLDER="/home/sgx/isl/t1/samples"
TIME=10
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
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 rm -f $TASK_FOLDER/password_checker_1
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 rm -rf $OP_FOLDER
ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 mkdir $OP_FOLDER
NO_TESTS=5
if [ ! -z  "$2" ]; then
    NO_TESTS=$2
fi

for (( i=1;i<=$NO_TESTS;i++ ))
do
    ssh -p $SSH_PORT -i ./id_rsa $USERNAME@127.0.0.1 timeout $TIME python3 $TASK_FOLDER/submit_3_1.py $SAMPLES_FOLDER/$i/traces $i
done

if ! scp -P $SCP_PORT -i ./id_rsa $USERNAME@127.0.0.1:$OP_FOLDER/oput_* .; then
    echo "No output files generated to read"
fi



