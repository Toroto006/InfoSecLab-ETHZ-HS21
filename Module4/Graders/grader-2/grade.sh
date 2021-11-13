PATH_TO_VM_IMAGE=VM_Task2.ova
USERNAME=isl
SCP_PORT=3022
SSH_PORT=3022
SCRIPT_FOLDER=/home/isl/scripts
TASK_FOLDER=/home/isl/t2

VM_NAME=VM_Task2_Grade

if ! VBoxManage list vms | grep $VM_NAME; then  
    VBoxManage import $PATH_TO_VM_IMAGE --vsys 0 --vmname $VM_NAME
else 
    echo "VM by name $VM_NAME already exists. Not importing new VM. To import a fresh VM delete the existing VM first"
fi

if ! VBoxManage list runningvms | grep $VM_NAME; then 
    VBoxManage startvm "$VM_NAME" --type headless
else 
    echo "VM by name $VM_NAME is already running. Not restarting it."
fi

sleep 5
rm -f ok*
rm -f flag-2*
echo "delete any local flag files"
ssh -p $SSH_PORT -i ./id_rsa  $USERNAME@localhost rm -rf $SCRIPT_FOLDER
ssh -p $SSH_PORT -i ./id_rsa  $USERNAME@localhost mkdir $SCRIPT_FOLDER
scp -P $SCP_PORT -i ./id_rsa  $1 $USERNAME@localhost:$SCRIPT_FOLDER
echo 'copied solution script to VM'
ssh -p $SSH_PORT -i ./id_rsa  $USERNAME@localhost rm -f $SCRIPT_FOLDER/flag-2*
echo 'removed any old flag files'

ssh -p $SSH_PORT -i ./id_rsa  $USERNAME@localhost timeout 30s python3 $SCRIPT_FOLDER/$1 &
sleep 30
ssh -p $SSH_PORT -i ./id_rsa  $USERNAME@localhost pkill -9 python3 

echo 'ran solution script'

ssh -p $SSH_PORT -i ./id_rsa  $USERNAME@localhost rm -f $TASK_FOLDER/ok*
echo 'removed any old ok files'

#check the E and P are running correctly
ssh -p $SSH_PORT -i ./id_rsa  $USERNAME@localhost timeout 30s python3 $TASK_FOLDER/test_setup.py 

#Kill E and P 
ssh -p $SSH_PORT -i ./id_rsa  $USERNAME@localhost pkill -9 node &

if scp -P $SCP_PORT -i ./id_rsa  $USERNAME@localhost:$TASK_FOLDER/ok_enclave .; then
    if scp -P $SCP_PORT -i ./id_rsa  $USERNAME@localhost:$TASK_FOLDER/ok_peripheral .; then
        if ! scp -P $SCP_PORT -i ./id_rsa $USERNAME@localhost:$SCRIPT_FOLDER/flag-2* .; then
            echo "No flag files generated to read"
        fi
    else
        echo "Peripheral not running. Not reading flag files. Exiting. "
    fi
else
    echo "Enclave not running. Did not check Peripheral state. Not reading flag files. Exiting. "
fi



