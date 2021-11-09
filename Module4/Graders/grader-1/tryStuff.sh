PATH_TO_VM_IMAGE=VM_Task1.ova
USERNAME=isl
SCP_PORT=3022
SSH_PORT=3022
SCRIPT_FOLDER=/home/isl/scripts
DATA_FOLDER=/home/isl/t1/

scp -P $SCP_PORT -i ./id_rsa -o StrictHostKeyChecking=no ./submit-1.py $USERNAME@localhost:$SCRIPT_FOLDER
echo 'copied solution script to VM'

ssh -p $SSH_PORT -i ./id_rsa -o StrictHostKeyChecking=no $USERNAME@localhost