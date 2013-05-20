#!/bin/bash
#
# LC 
#
# cron job which monitor the git repo and if there are updates
# submit a new batlab job
#
# 0 1-23/2 * * * ~/FingerPrint/FingerPrint/batlab/crontab.sh
#


. /etc/profile

echo starting crontab `date` >> ~/crontabLog

cd ~/FingerPrint/FingerPrint
if git pull | grep "Already up-to-date"; then 
	echo nothing new;
	exit 0;
fi

#there are new modification
cd batlab;
nmi_submit FingerPrint.run-spec;





