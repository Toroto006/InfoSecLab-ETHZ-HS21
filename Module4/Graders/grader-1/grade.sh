PATH_TO_VM_IMAGE=VM_Task1.ova
USERNAME=isl
SCP_PORT=3022
SSH_PORT=3022
SCRIPT_FOLDER=/home/isl/scripts
DATA_FOLDER=/home/isl/t1/

if ! VBoxManage list vms | grep VM_Task1_Grade; then  
    VBoxManage import $PATH_TO_VM_IMAGE --vsys 0 --vmname VM_Task1_Grade
else 
    echo "VM by name VM_Task1_Grade already exists. Not importing new VM. To import a fresh VM delete the existing VM first"
fi

if ! VBoxManage list runningvms | grep VM_Task1_Grade; then 
    VBoxManage startvm "VM_Task1_Grade" --type headless
else 
    echo "VM by name VM_Task1_Grade is already running. Not restarting it."
fi

sleep 5
scp -P $SCP_PORT -i ./id_rsa -o StrictHostKeyChecking=no $1 $USERNAME@localhost:$SCRIPT_FOLDER
echo 'copied solution script to VM'

ssh -p $SSH_PORT -i ./id_rsa -o StrictHostKeyChecking=no $USERNAME@localhost "timeout 60s python3 $SCRIPT_FOLDER/$1 &"
echo 'ran solution script'

ssh -p $SSH_PORT -i ./id_rsa -o StrictHostKeyChecking=no $USERNAME@localhost pkill -9 python3 &

if ! scp -P $SCP_PORT -i ./id_rsa -o StrictHostKeyChecking=no $USERNAME@localhost:$SCRIPT_FOLDER/flag1-* .; then
            echo "No flag files generated to read"
fi
