#!/usr/local/bin/bash 
#
# Cloud fuzzing on AWS EC2
# Requires winrm on path

# user_data="<powershell>
# Set-ExecutionPolicy Unrestricted
# icm $executioncontext.InvokeCommand.NewScriptBlock((New-Object Net.WebClient).DownloadString('https://gist.github.com/masterzen/6714787/raw')) -ArgumentList "adminPasswordHere"
# </powershell>"

# set -o errexit 			# exit when command fails
# set -o nounset 			# exit when attempting to use undeclared variables
# set -o xtrace 			# trace execution
# set -o pipefail 		# catch piped failures

load_config() 
{
    echo "Loading configuration file."
    source config.sh || { echo >&2 "Could not find configuration file.  Aborting." | tee -a log; exit 1; }
}

deps()
{
    echo "Checking dependencies." | tee log
    # bash v4 required for ridiculous associative arrays (see main)
    # http://www.artificialworlds.net/blog/2012/10/17/bash-associative-array-examples/
    if (( $BASH_VERSINFO < 4 )); 
    then 
	echo "Sorry, you need at least bash-4.0 to run this script." >&2; exit 1
    fi
    command -v go >/dev/null 2>&1 || { echo >&2 "Go required but not installed. Aborting." | tee -a log; exit 1; }
    command -v aws >/dev/null 2>&1 || { echo >&2 "Aws required but not installed. Aborting." | tee -a log; exit 1; }
    command -v zip >/dev/null 2>&1 || { echo >&2 "Zip required but not installed. Aborting." | tee -a log; exit 1; }
    command -v curl >/dev/null 2>&1 || { echo >&2 "Curl required but not installed. Aborting." | tee -a log; exit 1; }
    command -v winrm >/dev/null 2>&1 || { echo >&2 "Winrm required but not installed. Aborting." | tee -a log; exit 1; }
    command -v ssh >/dev/null 2>&1 || { echo >&2 "SSH required but not installed. Aborting." | tee -a log; exit 1; }
    command -v sshpass >/dev/null 2>&1 || { echo >&2 "sshpass required but not installed. Aborting." | tee -a log; exit 1; }
}

create_keypair()
{
    # Keypair is needed for security groups
    # and resetting Admin password of Windoze instance
    # TODO - if remote keypair exists, download?
    # TODO - if remote keypair exists, delete?
    if [ ! -f keypair ]; then
	echo "No keypair file found. Creating keypair." | tee -a log
	# create keypair 
	aws ec2 create-key-pair --key-name $KEYPAIR 2>&1 > keypair
	# extract key
	echo $(sed -n 2p keypair | awk 'BEGIN { FS = "\"" } ; { print $4 }') > $KEYPAIR.pem
	# change key permissions
	chmod 400 $KEYPAIR.pem 
    fi
}

create_security_group() 
{
    # Security group - required for control of instances
    if [[ $(aws ec2 describe-security-groups --group-names $SECURITY_GROUP 2>&1) == *Invalid* ]]
    then 
	echo "Creating Security Group" | tee -a log
	aws ec2 create-security-group --group-name $SECURITY_GROUP --description "Cloudfuzzer security group"
    else 
	echo "Security Group exists. Skipping creation." | tee -a log
    fi 
}

get_ip_cidr()
{
    # Access rules for security group
    # are based on /24 of machine IP
    # - Get the IP & convert to CIDR /24
    ip=$(curl -s -X GET http://checkip.amazonaws.com/)
    if [ $? != 0 ]
    then 
	echo "unable to get IP. exiting" | tee -a log
	exit 1
    else 
	echo $ip > ip
    fi
    # create cidr
    echo $(cut -d '.' -f1-3 ip).0/24 > cidr
}

check_sg_for_rule() {
    # Skip rule ingress/egress rule creation
    # if rule already exists for security group (for specific /24)
    rule_exists=$(ec2-describe-group $SECURITY_GROUP 2>&1 | grep -E "$1.*$2" | wc -l)
    echo $rule_exists
}

enable_rdp() {
    # Enable RDP traffic for Security Group
    # to reach instance over RDP (for debugging)
    # If enabled, skip
    echo "Checking for RDP route access." | tee -a log
    rdp_port=3389
    defined=$(check_sg_for_rule $rdp_port $cidr)
    if [ $defined -eq 0 ]
    then 
	echo "Enabling RDP" | tee -a log
	rdp_status=$(aws ec2 authorize-security-group-ingress \
	    --group-name $SECURITY_GROUP --protocol tcp --port $rdp_port --cidr $(cat cidr) 2>&1)
	[[ ! $rdp_status == *Invalid* ]] || echo "Error enabling rdp. Exiting." ; exit 1
    else
	echo "RDP network traffic enabled for Security Group" | tee -a log
    fi
}

enable_winrm() {
    # Enable WinRM traffic for Security Group
    # to reach instance over WinRM (for remote commands)
    # If enabled, skip
    echo "Checking for WinRM route access" | tee -a log
    winrm_port=5985
    defined=$(check_sg_for_rule $winrm_port $cidr)
    if [ $defined -eq 0 ]
    then
	# enable winrm 
	# aws inner portion - http://www.masterzen.fr/2014/01/11/bootstrapping-windows-servers-with-puppet/
	echo "Enabling Winrm" | tee -a log
	winrm_status=$(aws ec2 authorize-security-group-ingress \
	    --group-name $SECURITY_GROUP --protocol tcp --port $winrm_port --cidr $(cat cidr) 2>&1)
	[[ ! $winrm_status == *Invalid* ]] || echo "Error enabling winrm. Exiting." | tee -a log ; exit 1
    else
	echo "WinRM traffic enabled for Security Group" | tee -a log
    fi
}

enable_ssh()
{
    # SMB Traffic is blocked by ISPs
    # this requires the use of an SSH tunnel 
    # for mounting 
    # also provides encrypted connections 
    echo "Checking for SSH route access" | tee -a log
    ssh_port=22
    defined=$(check_sg_for_rule $ssh_port $cidr)
    if [ $defined -eq 0 ]
    then
	echo "- Enabling SSH" | tee -a log
	ssh_status=$(aws ec2 authorize-security-group-ingress \
	    --group-name $SECURITY_GROUP --protocol tcp --port $ssh_port --cidr $(cat cidr) 2>&1)
	[[ ! $smbtcp_status == *Invalid* ]] || echo "Error enabling smb/tcp. Exiting." ; exit 1
    else
	echo "SSH traffic enabled for Security Group" | tee -a log
    fi
}

authorize-ports() 
{
    # Create all ingress/egress rules for security group
    echo "Enabling network access in security groups." | tee -a log
    get_ip_cidr
    enable_rdp
    enable_winrm 
    enable_ssh #--enable_smbtcp <- tunnel
}

set_ami_password()
{
    # Modify userdata.txt to set ami password
    # with password from variable in script
    echo "Setting AMI password in USERDATA for template" | tee -a log
    echo "AMI password:" | tee -a log
    echo $(echo $AMI_PASSWORD | tr -d '"' | tr -d '\') | tee -a log
    # make a backup of userdata file before modification
    sed -i.bak "s/\"[^']*\"/$AMI_PASSWORD/g" $USER_DATA_FILE 
}

set_ami_config_url()
{
    # Modify userdata.txt to set ami config url
    # with url from variable in script
    echo "Setting remote url in USERDATA for template" | tee -a log
    echo "Remote url:" | tee -a log
    echo $USER_DATA_URL | tee -a log
    url=$(echo $USER_DATA_URL | sed -e 's/[\/&]/\\&/g')
    # create a backup file
    sed -i.bak "s/'[^']*'/$url/g" $USER_DATA_FILE
}

find_template_instances()
{
    # Find already running template instaces
    # TODO - test if undefined and skip
    echo "Searching for existing template instances." | tee -a log
    template_id=$(ec2-describe-instances --filter "tag-value=fuzzingtemplate" 2>&1 \
	| grep INSTANCE | awk '{print $2}')
    # Terminate running instances
    echo "Terminating existing template instances." | tee -a log
    ec2-terminate-instances $template_id 2>&1 

    # TODO - find and remove snapshots
}

launch_wintemplate_instance()
{
    # Launch the template instance 
    # with custom userdata configuration, keypair, security group.
    # write output to file ./instance
    find_template_instances
    echo "Launching Windows Template EC2 instance" | tee -a log
    # run new fuzzing instance based on AMI id 
    aws ec2 run-instances --image-id $BASE_AMI --count 1 --instance-type t1.micro --key-name $KEYPAIR --security-groups $SECURITY_GROUP --user-data "$(cat userdata.txt)" 2>&1 > instance
    # tag the instance as fuzzer template so it can be shutdown 
    # get instance log
    instance_id=$(grep InstanceId instance | awk 'BEGIN { FS = "\"" } ; { print $4 }')
    ec2-get-console-output $instance_id 2>&1 > instance_log
    echo "Tagging template image as fuzzer template" | tee -a log
    ec2-create-tags $instance_id --tag "stack=fuzzingtemplate"
}

wait_for_instance_setup()
{
    # poll system log for instance
    ec2-get-console-output $instance_id > instance_log 2>&1
    sleep 5
    # read last line of log, if it has message
    # print . character
    if [[ "$(tail -1 log)" == *Polling* ]]; then 
	echo -ne "." | tee -a log
    else
	echo -n "Polling for instance configuration completion" | tee -a log
    fi
    if grep -q 'Executing User Data' instance_log; then
	echo ""
	# echo -e "\n"
	echo "Template Configured"
    else
    	wait_for_instance_setup
    fi
}

poll_config_progress()
{
    # Read bootstrap log and exit 
    # when log indicates completion
    if [[ "$(tail -1 log)" == *Polling* ]]; then
	echo -ne "." | tee -a log
    else
	echo -n "Polling Bootstrap log." | tee -a log
    fi
    winrm -hostname $instance_ip -username Administrator -password $formatted_pass "type C:\Bootstrap.txt" > winrm_test
    if ! grep -q 'Restarting' winrm_test; then 
	sleep 5 
	poll_config_progress
    fi
}

test_winrm()
{
    # run winrm 
    instance_ip=$(ec2-describe-instances $instance_id | sed -n 2p | awk '{print $14}')
    echo "Testing WinRM connectivity." | tee -a log
    echo "instance ip"
    echo $instance_ip
    poll_config_progress
}

deregister_previous_ami()
{
    echo "Deregistering previous AMIs" | tee -a log
    
    # deregister prior AMI images
    # TODO - implement chck 
    previous_ami=$(ec2-describe-images -F "name=fuzzing-node-base" | grep IMAGE | awk '{print $2}')
    ec2-deregister $previous_ami 
}

check_template_fully_configured()
{
    # Check the template log using winrm 
    # to make sure it has been fully configured 
    # and undergone reboot 

    echo "checking for template fully configured" | tee -a log

    # currently monitor instance status to see codes available during reboot 
    # exit 1
    # winrm -hostname $instance_ip -username Administrator -password $AMI_PASSWORD "type C:\Bootstrap.txt" > template_status
    
}

bake_instance()
{
    check_template_fully_configured
    
    echo "Baking base image" | tee -a log

    deregister_previous_ami

    # bake base image
    aws ec2 create-image --instance-id $instance_id  \
	--name 'fuzzing-node-base' 2>&1 | \
	sed -n 2p 
    # get custom ami name 
    ami_id=$(ec2-describe-images | grep fuzzing-node-base | awk '{print $2}')
    echo "Base image successfully successfully baked." | tee -a log
    echo "AMI id: $ami_id" | tee -a log
}

create_custom_ami()
{
    # Create custom AMI 
    # from Windows Server 2008 base 
    # and install peach fuzzer 
    # + dependencies 
    echo "Setting up AWS instance." | tee -a log
    create_keypair
    create_security_group
    authorize-ports
    set_ami_password
    set_ami_config_url
    launch_wintemplate_instance
    wait_for_instance_setup
    test_winrm
}

check_ami_ready()
{
    # Check to make sure AMI 
    # has available status

    # echo "Checking AMI availability"
    ami_status=$(ec2-describe-images -F "name=fuzzing-node-base" | sed -n 1p | awk '{print $5}')
    if [ $ami_status = pending ]; then
	if [[ "$(tail -1 log)" == *Polling* ]]; then
	    echo -ne "." | tee -a log
	else
	    echo -n "Polling for AMI snapshot completion." | tee -a log
	fi
	sleep 5
	check_ami_ready
	
    fi
}

check_fuzzing_instance_ready()
{
    # Poll the fuzzing instance to make
    # sure it has booted (successfully)
    if [[ "$(tail -1 log)" == *Polling* ]]; then
	echo -ne "." | tee -a log
    else 
	echo -n "Polling Fuzzing Instance for boot completion." | tee -a log
    fi
    # ec2 system log check  
    instance_console=$(ec2-get-console-output $fuzzing_instance_id 2>&1 > instance_console)
    if ! grep -q 'Windows is Ready' instance_console; then 
	sleep 10
	check_fuzzing_instance_ready
    else
	echo "Fuzzing Instance Ready."
    fi
}

get_fuzzing_instance_ip()
{
   fuzzing_instance_ip=$(ec2-describe-instances -H $fuzzing_instance_id | grep NICASSOCIATION | awk '{print $2}')
   if test -z "$fuzzing_instance_ip"; then 
       get_fuzzing_instance_ip
   fi
}

skip_launch(){ 
    echo "Not implemented."
}

launch_fuzzing_instance()
{
    # TODO - make sure this works 

    DEBUG_SKIP_LAUNCH=false
    if $DEBUG_SKIP_LAUNCH -eq true; then 
	skip_launch
    else
	check_ami_ready
	if $CREATE_AMI; then 
	    echo "" | tee -a log
	    echo "AMI snapshot complete" | tee -a log
	fi
	# terminate prior instances
#	find_template_instances
	echo "Launching fuzzing machine instance." | tee -a log
	# check if ami_id is configured, if not then exit. Must be manually defined 
	# if create_custom_ami is skipped
	# create custom instance from AMI 
	# http://www.masterzen.fr/2014/01/11/bootstrapping-windows-servers-with-puppet/
	aws ec2 run-instances --image-id $ami_id --instance-type t1.micro --security-groups $SECURITY_GROUP --key-name $KEYPAIR 2>&1 > fuzzing_instance
	# get instance id 
	fuzzing_instance_id=$(grep InstanceId fuzzing_instance | awk 'BEGIN { FS = "\"" } ; { print $4 }')
	# declare "RUN_${CURRENT_RUN}[id]=${fuzzing_instance_id}"
	echo "RUN_1[id]: "

	tmp="RUN_${i}[id]"
	id=$(eval echo \${$tmp})
	echo $id

	get_fuzzing_instance_ip
	# declare "RUN_${CURRENT_RUN}[ip]=${fuzzing_instance_ip}"
	echo $fuzzing_instance_id > fuzzing_instance_id 
	echo $fuzzing_instance_ip > fuzzing_instance_ip
	check_fuzzing_instance_ready
    fi
}

kill_previous_ssh_sessions()
{
    # TODO - fix
    killall ssh
    port_proc=$(lsof -i:4455)
    if [[ -n $port_proc ]]; then
	kill $(echo $port_proc | sed -n 2p | awk '{print $2}')
    fi
}

generate_random_ssh_port()
{
    ssh_port=$(perl -e 'print int(rand(49151-1024))')
    port_used=$(lsof -i:$ssh_port)
    if [[ -n $port_used ]]; then 
	generate_random_ssh_port
    else
	echo $ssh_port
    fi
}

create_ssh_tunnel()
{
#    kill_previous_ssh_sessions

    # generate random user port 
    ssh_port=$(generate_random_ssh_port)

    # disable fingerprint verification and 
    # pipe the password on the commandline 
    # because we hate security
    # http://linuxcommando.blogspot.com/2008/10/how-to-disable-ssh-host-key-checking.html
    # ----
    # create a local port 4455 that is the remote SMB server over SSH tunnel
    echo "Creating SSH tunnel to fuzzing instance." | tee -a log
    sshpass -p $formatted_pass ssh -f -N -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -L $ssh_port:127.0.0.1:445 Administrator@$fuzzing_instance_ip
}

mount_instance()
{
    # TODO - fix
    create_ssh_tunnel
    declare "RUN_${CURRENT_RUN}[sshport]=${ssh_port}"
    # add ssh port to array
    echo "Mounting instance" | tee -a log
    # http://www.masterzen.fr/2014/01/11/bootstrapping-windows-servers-with-puppet/
    # test if the mountpoint is mounted
    RUN_MOUNTPOINT=$BASE_MOUNTPOINT/run_$CURRENT_RUN
    declare "RUN_${CURRENT_RUN}[mountpoint]=${RUN_MOUNTPOINT}"
    mkdir -p $RUN_MOUNTPOINT
    mount_smbfs //Administrator:$formatted_pass@127.0.0.1:$ssh_port/C$ $RUN_MOUNTPOINT
}

install_seeds()
{
    # TODO - make sure this works 
    echo "Installing seed files to instance" 
    if [ -e $SEEDS_DIR ]; then 
	# install seed files for fuzzer 
	mkdir -p $RUN_MOUNTPOINT/fuzzing_run
	mkdir -p $RUN_MOUNTPOINT/fuzzing_run/logs
	mkdir -p $RUN_MOUNTPOINT/fuzzing_run/seeds
	cp -r $SEEDS_DIR $RUN_MOUNTPOINT/fuzzing_run/seeds/
    else
	echo "Seeds Directory not found. Exiting"
	exit 1 
    fi
}

create_peachpit_template()
{
    # TODO - make sure this works 
    echo "Checking for Peach Pit template"
    # check that the peach pit file exists 
    # this is sloppy - breaks if run from different path 
    if [ ! -e "$(pwd)/peach_templates/template.xml" ]; then 
	echo "Peach Pit template not found. Exiting" 
	exit 1 
    fi 
    # this is where most of the XML 
    # file parsing to transform the 
    # config will take place 
    # for right now just assume that new_template.xml 
    # is the correctly configured file   
}

install_windbg()
{
    # http://www.microsoft.com/en-us/download/confirmation.aspx?id=8442
    # GRMSDKIAI_EN_DVD/Setup/WinSDKDebuggingTools_amd64
    echo "Installing windbg"
    cp $(pwd)/windeps/dbg_amd64.msi $RUN_MOUNTPOINT
    winrm -hostname $fuzzing_instance_ip -username Administrator -password $formatted_pass \
	"msiexec /i C:\dbg_amd64.msi /quiet"
}

install_template()
{
    # TODO - make sure this works 
    # Install the Peach Pit file 
    # onto the EC2 instance over local mountpoint 
    cp $(pwd)/peach_templates/new_template.xml $RUN_MOUNTPOINT/fuzzing_run/
}

start_fuzzing_run()
{
    # TODO - make sure this works 
    # Remotely run winrm to execute task and redirect output to remote machine 
    # execute winrm command on remote machine to launch peach 
    # and send all output to log
    install_windbg
    echo "Running Peach"
    winrm -hostname $fuzzing_instance_ip -username Administrator -password $formatted_pass "Peach.exe C:\fuzzing_run\new_template.xml" > fuzzing_log 2>&1 &
    winrm_pid="$!"
    declare "RUN_${CURRENT_RUN}[pid]=${winrm_pid}"
    echo "PID of fuzzing command: $winrm_pid"
    echo "Writing results to fuzzing_log"
}

internal_fuzzing_run()
{
    # TODO - make sure this works 
    # Binary is part of Windows 
    # no need to install
    launch_fuzzing_instance 
    # there may have to be a wait here 
    mount_instance
    install_seeds
    create_peachpit_template 
    install_template 
    start_fuzzing_run 
}

external_fuzzing_run()
{ 
    # TODO - make sure this works 
    # copy external binary over to instance 
    echo "external fuzzing run not implemented"
    exit 1
}

launch_fuzzing_run()
{
    if [ "$BINARY_INTERNAL" = true ]; then 
	internal_fuzzing_run
    elif [ "$BINARY_EXTERNAL" = true ]; then 
	external_fuzzing_run 
    fi 
}

launch_fuzzing_runs()
{
    # Run fuzzing run for each machine
    # generate unique mountpoint and sshport 
    # store the results
    CURRENT_RUN=0
    for i in $(seq 1 $NUM_INSTANCES)
    do 
	declare -A "RUN_$i"
	CURRENT_RUN=$i
	echo "Launching run $i"
	launch_fuzzing_run
    done
    for i in $(seq 1 $NUM_INSTANCES)
    do 
	echo "Data for run $i:"
	for K in $(eval echo \${!RUN_${i}[@]});
	do
	    tmp="RUN_${i}[$K]"
	    id=$(eval echo \${$tmp})
	    echo $id
	done
    done
}

main()
{
    load_config
    deps 
    formatted_pass=$(echo $AMI_PASSWORD | tr -d '"' | tr -d '\')
    if [ "$CREATE_AMI" = true ]; then
	echo "BASE AMI: $BASE_AMI"
	create_custom_ami
	bake_instance
    else
	echo "Skipping custom AMI creation."
    fi
    launch_fuzzing_runs
}

usage() 
{
    echo "usage"
    exit 0
}

# Arguments parsing
while getopts "hce" opt; do
    case $opt in
	h)
	    usage
	    ;;
	e)
	    echo "executing e2e" >&2
	    main
	    ;;
	c)
	    echo "Creating custom AMI." >&2
	    create_custom_ami
	    ;;
	\?)
	    echo "Invalid option: -$OPTARG" >&2
	    ;;
	:)
	    echo "Option -$OPTARG requires an argument." >&2
	    exit 1
	    ;;
    esac
done 
