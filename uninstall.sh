#!/bin/bash

uninstall_daemon()
{
#stopping service
sudo systemctl stop $1
#disabling service
sudo systemctl disable $1

#check if service file exists then delete it
if [ -f /etc/systemd/system/$1 ]
then
	sudo rm -rf /etc/systemd/system/$1
else
	echo "/etc/systemd/system/$1 does not exist"
fi

#check if log folder exists then deleted it
service_name=$(echo $1 | cut -d "." -f 1)
if [ -d /var/log/$service_name ]
then
	sudo rm -rf /var/log/$service_name
else
	echo "/var/log/$service_name not found"
fi

#check if binary exists then delete it
script_name="${service_name}.sh"
if [ -f /bin/$script_name ]
then
        sudo rm -rf /bin/$script_name
else
        echo "/bin/$script_name does not exist"
fi

}


uninstall_daemon encrypt.service
uninstall_daemon decrypt.service
