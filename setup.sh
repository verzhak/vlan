#!/bin/bash

init()
{
	sudo ip link set dev vboxnet0 up
	sudo sysctl -q net.core.bpf_jit_enable=1

	echo Init
}

reinit()
{
	flush
	init
}

flush()
{
	echo Flush
}

############################################################################ 

if [[ $1 == "--init" ]]
then

	init

elif [[ $1 == "--reinit" ]]
then

	reinit

elif [[ $1 == "--flush" ]]
then

	flush

fi

