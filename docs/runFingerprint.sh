#!/bin/bash
#
# LC
#
# script to run fingerprint on a set of application

apps="amber"
email="clem@sdsc.edu"



. /etc/profile
cd $HOME
. .bashrc

function failure(){
    echo -n `date` - ERROR >> tmplog
    if [ "$1" == 'y' ];then 
        echo -n verification >> tmplog
    elif [ "$1" == "i" ];then
        echo -n integrity >> tmplog 
    fi
    cat error >> tmplog
    echo >> tmplog
    cat tmplog | mail -s "error `hostname`" $email
    cat tmplog >> log
    rm tmplog
    rm error
}


for i in $apps; do
    cd $i
    fingerprint -y > error || failure y $i
    fingerprint -i > error || failure i $i
    cd ..
done


