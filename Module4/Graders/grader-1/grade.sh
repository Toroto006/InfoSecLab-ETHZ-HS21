PATH_TO_VM_IMAGE=VM_Task1.ova
USERNAME=isl
SCP_PORT=3022
SSH_PORT=3022
SCRIPT_FOLDER=/home/isl/scripts
DATA_FOLDER=/home/isl/t1/

if ! VBoxManage list vms | grep VM_Task1_Grade; then  
    VBoxManage import $PATH_TO_VM_IMAGE --vsys 0 --vmname VM_Task1_Grade
else 
    echo "[GRADER] VM by name VM_Task1_Grade already exists. Not importing new VM. To import a fresh VM delete the existing VM first"
fi

if ! VBoxManage list runningvms | grep VM_Task1_Grade; then 
    VBoxManage startvm "VM_Task1_Grade" --type headless
else 
    echo "[GRADER] VM by name VM_Task1_Grade is already running. Not restarting it."
fi

sleep 5
scp -P $SCP_PORT -i ./id_rsa -o StrictHostKeyChecking=no $1 $USERNAME@localhost:$SCRIPT_FOLDER
echo '[GRADER] copied solution script to VM'

#ssh -p $SSH_PORT -i ./id_rsa -o StrictHostKeyChecking=no $USERNAME@localhost "python3 $SCRIPT_FOLDER/$1 &"
ssh -p $SSH_PORT -i ./id_rsa -o StrictHostKeyChecking=no $USERNAME@localhost "bash -c 'nohup python3 $SCRIPT_FOLDER/$1 > /dev/null 2>&1 &'"
echo '[GRADER] sent command to execute solution script; waiting for 60 seconds...'
sleep 60
ssh -p $SSH_PORT -i ./id_rsa -o StrictHostKeyChecking=no $USERNAME@localhost "bash -c 'nohup pkill -9 python3 > /dev/null 2>&1 &'"
ssh -p $SSH_PORT -i ./id_rsa -o StrictHostKeyChecking=no $USERNAME@localhost "bash -c 'nohup pkill -9 gdb > /dev/null 2>&1 &'"
echo '[GRADER] ran solution script'
sleep 3

ssh -p $SSH_PORT -i ./id_rsa -o StrictHostKeyChecking=no $USERNAME@localhost "bash -c 'nohup python3 $DATA_FOLDER/test_setup.py > $SCRIPT_FOLDER/testlog.otp 2>&1 &'"
echo '[GRADER] ran component healthcheck'

if ! scp -P $SCP_PORT -i ./id_rsa -o StrictHostKeyChecking=no $USERNAME@localhost:$SCRIPT_FOLDER/flag1-* .; then
            echo "[GRADER] No flag files generated to read"
fi
sleep 1
if ! scp -P $SCP_PORT -i ./id_rsa -o StrictHostKeyChecking=no $USERNAME@localhost:$SCRIPT_FOLDER/testlog.otp .; then
            echo "[GRADER] No healthcheck files generated to read"
fi