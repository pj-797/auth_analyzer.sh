#!/bin/bash
#--------------------------------------------------------------------------------
#	auth_analyzer.sh (For Linux)
#	To provide overall view of auth.log
#	Creator: Zi_WaF
#	Group: Centre for Cybersecurity
#	Usage: bash auth_analyzer.sh <auth.log>
#	Need geoip installed & updated (see https://installati.one/install-geoip-bin-kalilinux/)
#--------------------------------------------------------------------------------

function trap_all(){  	# set up for any interruptions and exit program cleanly
		rm -r /tmp/set.txt 2>/dev/null
		echo -e "\nProgram interrupted."
		exit
}
function bin_check(){  	# install needed applications; assuming new system
	#sudo apt-get update -y #&& sudo apt-get upgrade -y && sudo apt-get full-upgrade -y && sudo apt autoremove -y	# full upgrade system
	tput reset												# clean reset of terminal, instead of using clear
	#echo -e " \033[0;32m[+] Full Upgrade Complete.\033[0m"
	
	if [ "$(which geoiplookup)" = "/usr/bin/geoiplookup" ]	# check for geoiplookup
	then
		echo -e " \033[0;32m[+] GeoIP Detected.\033[0m"
	else
		echo -e " \033[1;31m[-] GeoIP NOT Detected.\033[0m Installing \e[1m\"Geo-IP\"\e[0m... Please wait."
		sudo DEBIAN_FRONTEND=noninteractive apt install geoip-bin -y &> /dev/null		# install geoip-bin
		echo -e " \033[0;32m[+] GeoIP Detected.\033[0m"
	fi
}
function time_period(){		# format and display the time differences
	
			secs="$(echo -e $(( $(date -d "$2" "+%s") - $(date -d "$1" "+%s") )))"
			echo -e "($((secs/86400)) days $((secs%86400/3600)) hours $((secs%3600/60)) minutes $((secs%60)) seconds)\n"
}
function log_details(){	
	echo -e "\n\033[1mHostname: \033[0m"$(cat auth.log | awk '{print $4}' | sort | uniq)"\n"
	fts=$(cat $1 | head -n 1 | awk '{print $1, $2, $3}')  	# first timestamps
	ets=$(cat $1 | tail -n 1 | awk '{print $1, $2, $3}')	# end timestamps
	echo -e "\033[1mDate & Time of ($1):\n\e[4m$fts\033[0m  to  \033[1m\e[4m$ets\e[4m\033[0m" 
	time_period "$fts" "$ets"
}
function most_failed_attempts(){		# failed attempts for passwords and invalid users
	IFS=$'\n'
	most_failed=$(cat $1 | awk '$6=="Failed"' | grep -i "Failed Password" | awk '{print$NF,$(NF-3)}' | sort | uniq -c | sort -nr | head -n 10 | tr -s '[:blank:]' '\t' | column -s $'\t' -t)
	
	echo -e "\033[1m\e[4m\nFailed Attempts (Top 10)\033[0m\e[0m (Total Attempts: $(cat $1 | awk '$6=="Failed"' | wc -l))\n"
	echo -e "\033[1mMost Failed Attempts:\033[0m\e[0m\n\033[1m\e[4m  Att   Svc   IP Address      Country    Attempted as     Activity Period                  \033[0m\e[0m"
	
	for i in $most_failed		
	do
		mf_ip=$(echo $i | awk '{print $NF}')
		mf_user=$(cat $1 | awk '$6=="Failed"' | grep -i "Failed Password" | grep $mf_ip | awk '{print$(NF-5)}' | sort | uniq -c | sort -nr | head -n 1)
		country=$(geoiplookup $mf_ip | awk '{print $4}' | tr -d ',')
		d1=$(cat $1 | grep $mf_ip | head -n 1 | awk '{print $1, $2, $3}')
		d2=$(cat $1 | grep $mf_ip | tail -n 1 | awk '{print $1, $2, $3}')
		activity=$(echo -e "$d1 to $d2\t" $(time_period "$d1" "$d2"))
		VAR3=$(paste <(echo $i ) <(echo $country) <(echo $mf_user) <(echo $activity))
		echo "$VAR3"
	done
}
function most_failed_invalid_username(){	# failed attempts by invalid users
	IFS=$'\n'
	mf_invalidname=$(cat $1 | awk '$6=="Failed"' | grep -i "Failed password for invalid user" | awk '{print $11}' | sort | uniq -c | sort -nr | head | tr '\n' "\s" | column -s $'\t' -t)
	mf_invalid=$(cat $1 | awk '$6=="Failed"' | grep -i "Failed password for invalid user" | awk '{print $NF,$11,$13}' | sort -k 3 | uniq -c | sort -nr | head -n 10 | tr -s '[:blank:]' '\t' | column -s $'\t' -t)
	echo -e "\033[1m\nInvalid Username (for Login):\033[0m (Total Attempts: $(cat $1 | awk '$6=="Failed"' | grep -i "Failed password for invalid user" | wc -l))"
	echo -e "$mf_invalidname"
	echo -e "\033[1m\e[4m  Att  Svc  User    IP Address        Country    Activity Period                    \e[0m"
	for i in $mf_invalid
	do
		mf_invalid_ip=$(echo $i | awk '{print $NF}')
		country=$(geoiplookup $mf_invalid_ip | awk '{print $4}' | tr -d ',')
		d1=$(cat $1 | grep $mf_invalid_ip | head -n 1 | awk '{print $1, $2, $3}')
		d2=$(cat $1 | grep $mf_invalid_ip| tail -n 1 | awk '{print $1, $2, $3}')
		activity=$(echo -e "$d1 to $d2" $(time_period "$d1" "$d2"))
		VAR3=$(paste <(echo $i) <(echo $country) <(echo $activity))
		echo "$VAR3"
	done
}
function most_failed_valid_username(){		# failed attempts by valid users
	rm -r /tmp/set.txt 2>/dev/null
	mv_username=$(cat $1 | awk '$6=="Failed"' | grep -vi "Failed password for invalid user" | grep -vw "root"  | awk '{print$(NF-5)}' | sort | uniq -c | sort -nr | head -n 10)
	username=$(cat $1 | awk '$6=="Failed"' | grep -vi "Failed password for invalid user" | grep -vw "root"  | awk '{print$(NF-5)}' | sort | uniq -c | sort -nr | head -n 10 | awk '{print $2}')
	echo -e "\033[1m\nValid Username (for Login):\033[0m (Total Attempts: $(cat $1 | awk '$6=="Failed"' | grep -vi "Failed password for invalid user" | grep -vw "root" | wc -l)) \n\033[1m\e[4m Svc    User   Total       IP Addresses       \e[0m"
	for i in $username 		
	do
		#echo | awk -v i=$i '$(NF-5)==i'
		user_ip=$(cat $1 | awk '$6=="Failed"' | grep -vi "Failed password for invalid user" | grep -vw "root"  | awk -v i=$i '$(NF-5)==i'  | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort -r | tr '\n' "|")
		for ip in $(echo $user_ip | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}")		# loop to check country of IP address
		do
			country=$(geoiplookup $ip | awk '{print $4}' | tr -d ',')
			#set_ips=$(echo $ip "("$country")" | tr '\n' "|")
			echo " "$ip "("$country") " | tr '\n' "|" >> /tmp/set.txt				# using a temp file as a set for each user
			#echo " "$ip "("$country")" >> /tmp/set.txt
		done  
		user_svc=$(cat $1 | awk '$6=="Failed"' | grep -vi "Failed password for invalid user" | grep -vw "root"  | awk -v i=$i '$(NF-5)==i'  | awk '{print $NF}' | sort | uniq )
		number_ip=$(cat $1 | awk '$6=="Failed"' | grep -vi "Failed password for invalid user" | grep -vw "root"  | awk -v i=$i '$(NF-5)==i'  | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | wc -l)
		VAR3=$(paste <(echo $user_svc) <(echo $i) <(echo $number_ip) <(cat /tmp/set.txt) )
		echo "$VAR3"
		rm -r /tmp/set.txt
	done
}
function most_failed_as_Root(){		# failed attempts as Root
	IFS=$'\n'
	as_root=$(cat $1 | awk '$6=="Failed"' | grep -w "Failed password" | awk '$(NF-5)=="root"' | awk '{print$NF,$(NF-5),$(NF-3)}' | sort -k 2 | uniq -c | sort -nr | head -n 10 | tr -s '[:blank:]' '\t' | column -s $'\t' -t)
	echo -e "\033[1m\nAs root (for Login):\033[0m (Total Attempts: $(cat $1 | awk '$6=="Failed"' | grep -w "Failed password" | awk '$(NF-5)=="root"' | wc -l))\n\033[1m\e[4m  Att   Svc   User  IP Address        Country    Activity Period                   \033[0m\e[0m"
	for i in $as_root
	do
		as_root_ip=$(echo $i | awk '{print $NF}')
		country=$(geoiplookup $as_root_ip | awk '{print $4}' | tr -d ',')
		d1=$(cat $1 | grep $as_root_ip | head -n 1 | awk '{print $1, $2, $3}')
		d2=$(cat $1 | grep $as_root_ip| tail -n 1 | awk '{print $1, $2, $3}')
		activity=$(echo -e "$d1 to $d2" $(time_period "$d1" "$d2"))
		VAR3=$(paste <(echo $i" ") <(echo $country) <(echo $activity))
		echo "$VAR3"
	done
}
function success_as_Root(){			# successful logins as Root
	IFS=$'\n'
	as_root=$(cat $1 | awk '$6=="Accepted"' | grep -w "Accepted password" | awk '$(NF-5)=="root"' | awk '{print$NF,$(NF-5),$(NF-3)}' | sort -k 2 | uniq -c | sort -nr | head -n 10 | tr -s '[:blank:]' '\t' | column -s $'\t' -t)
	echo -e "\033[1m\e[4m\nSuccessful Attempts (Top 10)\e[0m\033[0m (Total: $(cat $1 | awk '$6=="Accepted"' | grep -w "Accepted password" | wc -l))"
	echo -e "\033[1m\nAs root (for Login):\033[0m (Total Attempts: $(cat $1 | awk '$6=="Accepted"' | grep -w "Accepted password" | awk '$(NF-5)=="root"' | wc -l))\n\033[1m\e[4m Att Svc   User  IP Address   Country    Activity Period                   \033[0m\e[0m"
	for i in $as_root
	do
		as_root_ip=$(echo $i | awk '{print $NF}')
		country=$(geoiplookup $as_root_ip | awk '{print $4}' | tr -d ',')
		d1=$(cat $1 | grep $as_root_ip | head -n 1 | awk '{print $1, $2, $3}')
		d2=$(cat $1 | grep $as_root_ip| tail -n 1 | awk '{print $1, $2, $3}')
		activity=$(echo -e "$d1 to $d2" $(time_period "$d1" "$d2"))
		VAR3=$(paste <(echo $i" ") <(echo $country) <(echo $activity))
		echo "$VAR3"
	done
}
function success_as_Others(){		# successful logins as Other Users
	IFS=$'\n'
	as_others=$(cat $1 | awk '$6=="Accepted"' | grep -i "Accepted password"  | awk '$(NF-5)!="root"' | awk '{print$NF, $(NF-5), $(NF-3)}' | sort | uniq -c | sort -nr | head -n 10 | tr -s '[:blank:]' '\t' | column -s $'\t' -t)
	others=$(cat $1 | awk '$6=="Accepted"' | grep -i "Accepted password"  | awk '$(NF-5)!="root"' | awk '{print $(NF-5)}' | sort | uniq -c | sort -nr | head -n 10 | tr -s '[:blank:]' '\t' | column -s $'\t' -t)
	echo -e "\033[1m\nOther Users:\033[0m (Total Attempts: $(cat $1 | awk '$6=="Accepted"' | grep -i "Accepted password"  | awk '$(NF-5)!="root"' | wc -l))\e[0m"
	echo "$others"
	echo -e "\033[1m\e[4m Att  Svc     User      IP Address    Country     Activity Period                   \e[0m"
	for i in $as_others
	do
		as_others_ip=$(echo $i | awk '{print $NF}')
		country=$(geoiplookup $as_others_ip | awk '{print $4}' | tr -d ',')
		d1=$(cat $1 | grep $as_others_ip | head -n 1 | awk '{print $1, $2, $3}')
		d2=$(cat $1 | grep $as_others_ip | tail -n 1 | awk '{print $1, $2, $3}')
		activity=$(echo -e "$d1 to $d2" $(time_period "$d1" "$d2"))
		VAR3=$(paste <(echo $i) <(echo $country) <(echo $activity))
		echo "$VAR3"
	done
}

if [ -z "$1" ]
then
    echo -e "No input.\nExample: \033[0;36mbash auth_analyzer_2.sh <auth log>\033[0m\nAdditional info: Need geoip installed & updated"	 # if no arguments was passed
else
	trap "trap_all" 2
	bin_check
	log_details $1
	most_failed_attempts $1
	most_failed_invalid_username $1
	most_failed_valid_username $1
	most_failed_as_Root $1
	success_as_Root $1
	success_as_Others $1
fi
