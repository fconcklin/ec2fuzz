#!/bin/bash 
#
# Cloud fuzzing on AWS EC2

BASE_AMI="ami-16197726"		 # windows server 2008 r2
KEYPAIR="CFKeypair"		 # TODO - factor out keypair
SECURITY_GROUP="CFSecurityGroup" # TODO - factor out security group
USER_DATA_FILE="userdata.txt"	 # TODO - factor out user data
USER_DATA_URL="https://gist.githubusercontent.com/fconcklin/10331784/raw/4bbbf1b81213e55ea65385714ad678e669a30859/Bootstrap-EC2-Windows-CloudInit.ps1"
PATH_TO_WINRM=""
AMI_PASSWORD=$(cat password)
RESULT_AMI_NAME=""		# TODO - factor out baked ami name

# TODO - do automatic region setting
# if you don't have correct region configured
# everything fails
export EC2_URL="https://ec2.us-west-2.amazonaws.com"

deps()
{
    # TODO - dependency checks
    echo "Checking dependencies."
    # go - required for winrm
    command -v go >/dev/null 2>&1 || { echo >&2 "Go required but not installed.  Aborting."; exit 1; }
    # aws - required for ec2 service comm
    command -v aws >/dev/null 2>&1 || { echo >&2 "Aws required but not installed.  Aborting."; exit 1; }
    # zip - required for compressing puppet scripts
    command -v zip >/dev/null 2>&1 || { echo >&2 "Zip required but not installed.  Aborting."; exit 1; }
    # curl - required for AWS IP check for security group ruls
    command -v curl >/dev/null 2>&1 || { echo >&2 "Curl required but not installed.  Aborting."; exit 1; }
#    command -v winrm >/dev/null 2>&1 || { echo >&2 "Winrm required but not installed.  Aborting."; exit 1; }
}

create_keypair()
{
    # Keypair is needed for security groups
    # and resetting Admin password of Windoze instance
    # TODO - if remote keypair exists, download?
    # TODO - if remote keypair exists, delete?
    if [ ! -f keypair ]
    then 
	echo "No keypair file found. Creating keypair."
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
	echo "Creating Security Group"
	aws ec2 create-security-group --group-name $SECURITY_GROUP --description "Cloudfuzzer security group"
    else 
	echo "Security Group exists. Skipping creation."
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
	echo "unable to get IP. exiting"
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
    # port=$1
    # cidr=$2
    rule_exists=$(ec2-describe-group $SECURITY_GROUP 2>&1 | grep -E "$1.*$2" | wc -l)
    echo $rule_exists
}

enable_rdp() {
    # Enable RDP traffic for Security Group
    # to reach instance over RDP (for debugging)
    # If enabled, skip
    echo "Checking for RDP route access."
    rdp_port=3389
    defined=$(check_sg_for_rule $rdp_port $cidr)
    if [ $defined -eq 0 ]
    then 
	echo "Enabling RDP"
	rdp_status=$(aws ec2 authorize-security-group-ingress \
	    --group-name $SECURITY_GROUP --protocol tcp --port $rdp_port --cidr $(cat cidr) 2>&1)
	[[ ! $rdp_status == *Invalid* ]] || echo "Error enabling rdp. Exiting." ; exit 1
    else
	echo "RDP network traffic enabled for Security Group"
    fi
}

enable_winrm() {
    # Enable WinRM traffic for Security Group
    # to reach instance over WinRM (for remote commands)
    # If enabled, skip
    echo "Checking for WinRM route access"
    winrm_port=5985
    defined=$(check_sg_for_rule $winrm_port $cidr)
    if [ $defined -eq 0 ]
    then
	# enable winrm - http://www.masterzen.fr/2014/01/11/bootstrapping-windows-servers-with-puppet/
	echo "Enabling Winrm"
	winrm_status=$(aws ec2 authorize-security-group-ingress \
	    --group-name $SECURITY_GROUP --protocol tcp --port $winrm_port --cidr $(cat cidr) 2>&1)
	[[ ! $winrm_status == *Invalid* ]] || echo "Error enabling winrm. Exiting." ; exit 1
    else
	echo "WinRM traffic enabled for Security Group"
    fi
}

enable_smbtcp()
{
    # Enable SMB traffic for Security Group
    # to reach instance over Samba (for remote mounting)
    # If enabled, skip
    echo "Checking for SMB/TCP route access"
    smbtcp_port=445
    defined=$(check_sg_for_rule $smbtcp_port $cidr)
    if [ $defined -eq 0 ]
    then
	# enable smb/tcp - http://www.masterzen.fr/2014/01/11/bootstrapping-windows-servers-with-puppet/
	echo "- Enabling SMB/TCP"
	smbtcp_status=$(aws ec2 authorize-security-group-ingress \
	    --group-name $SECURITY_GROUP --protocol tcp --port $smbtcp_port --cidr $(cat cidr) 2>&1)
	[[ ! $smbtcp_status == *Invalid* ]] || echo "Error enabling smb/tcp. Exiting." ; exit 1
    else
	echo "SMB/TCP traffic enabled for Security Group"
    fi
}

authorize-ports() 
{
    # Create all ingress/egress rules 
    # for security group.
    echo "Enabling network access in security groups."
    enable_rdp ; enable_winrm ; enable_smbtcp 
}

set_ami_password()
{
    # Modify userdata.txt to set ami password
    # with password from variable in script
    echo "Setting AMI password in USERDATA for template"
    echo "AMI password:"
    echo $(echo $AMI_PASSWORD | tr -d '"')
    # make a backup of userdata file
    sed -i.bak "s/\"[^']*\"/$AMI_PASSWORD/g" $USER_DATA_FILE 
}

set_ami_config_url()
{
    # Modify userdata.txt to set ami config url
    # with url from variable in script
    echo "Setting remote url in USERDATA for template"
    echo "Remote url:"
    echo $USER_DATA_URL
    url=$(echo $USER_DATA_URL | sed -e 's/[\/&]/\\&/g')
    sed -i.back "s/'[^']*'/$url/g" $USER_DATA_FILE
    exit 1
}

launch_wintemplate_instance()
{
    # Launch the template instance 
    # with custom userdata configuration, keypair, security group.
    # write output to file ./instance
    echo "Launching Windows Template EC2 instance"
    aws ec2 run-instances --image-id $BASE_AMI --count 1 --instance-type t1.micro \
	--key-name $KEYPAIR --security-groups $SECURITY_GROUP --user-data "$(cat userdata.txt)" 2>&1 > instance
}

get_instance_log()
{
    # Get system log of instance for pre-configured checks. 
    # Write output to file ./instance_log.
    instance_id=$(grep InstanceId instance | awk 'BEGIN { FS = "\"" } ; { print $3 }')
    ec2-get-console-output $instance_id 2>&1 > instance_log
}

wait_for_instance_setup()
{
    # poll system log for instance
    # TODO - verify this works
    while : ; do
	echo "Polling for instance configuration completion"
	get_instance_log
	[[ $(cat instance_log) == *RDPCERTIFICATE* ]] || break
	echo "Instance not yet configured."
	sleep 5
    done
}

test_winrm()
{
    # TODO - Fix test 
    # run winrm 
    instance_ip=$(ec2-describe-instances $instance_id | sed -n 2p | awk '{print $14}')
    $( cd $PATH_TO_WINRM/bin/ ; \
         winrm_test=$(./winrm -hostname $instance_ip -username Administrator -password $AMI_PASSWORD "ipconfig /all")) 
    [[ ! $(echo $winrm_test | wc -l) -eq 0 ]] || "Winrm test failed. Exiting" ; exit 1
}

mount_instance()
{
    # TODO - mount image for puppet scripts upload
    # http://www.masterzen.fr/2014/01/11/bootstrapping-windows-servers-with-puppet/
    sudo mkdir -p /mnt/win
    sudo mount -t cifs -o user="Administrator$AMI_PASSWORD",uid="$USER",forceuid "//<instance-ip>/C\$/Users/Administrator/AppData/Local/Temp" /mnt/win
}

install_peach()
{
    # http://www.masterzen.fr/2014/01/11/bootstrapping-windows-servers-with-puppet/
    zip -q -r /mnt/win/puppet-windows.zip manifests/peach.pp modules -x .git
    ./winrm \
	"7z x -y -oC:\\Users\\Administrator\\AppData\\Local\\Temp\\ C:\\Users\\Administrator\\AppData\\Local\\Temp\\puppet-windows.zip | FIND /V \"ing  \""
    ./winrm \
	"\"C:\\Program Files (x86)\\Puppet Labs\\Puppet\\bin\\puppet.bat\" apply --debug --modulepath C:\\Users\\Administrator\\AppData\\Local\\Temp\\modules C:\\Users\\Administrator\\AppData\\Local\\Temp\\manifests\\site.pp"
}

install_peach_farmer()
{
    # http://www.masterzen.fr/2014/01/11/bootstrapping-windows-servers-with-puppet/
    zip -q -r /mnt/win/puppet-windows.zip manifests/peachfarmer.pp modules -x .git
    ./winrm \
	"7z x -y -oC:\\Users\\Administrator\\AppData\\Local\\Temp\\ C:\\Users\\Administrator\\AppData\\Local\\Temp\\puppet-windows.zip | FIND /V \"ing  \""
    ./winrm \
	"\"C:\\Program Files (x86)\\Puppet Labs\\Puppet\\bin\\puppet.bat\" apply --debug --modulepath C:\\Users\\Administrator\\AppData\\Local\\Temp\\modules C:\\Users\\Administrator\\AppData\\Local\\Temp\\manifests\\site.pp"
}

bake_instance()
{
    # bake base image
    aws ec2 create-image --instance-id $instance_id --name 'fuzzing-node-base'
}

stop_template_instance()
{
    # TODO - stop template instance
    exit 1
}

create_custom_ami()
{
    echo "Setting up AWS instance."
    deps
    create_keypair
    create_security_group
    authorize-ports
    set_ami_password
    set_ami_config_url
    launch_wintemplate_instance
    wait_for_instance_setup
    test_winrm
    mount_instance
    install_peach
    install_peach_farmer
#    bake_instance
#    stop_template_instance
}

main()
{
    echo "BASE AMI: $BASE_AMI"

    create_custom_ami
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
