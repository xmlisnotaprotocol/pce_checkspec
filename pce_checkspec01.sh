#!/usr/bin/env bash
# This script serves as precheck on the PCE required spec. It helps to identify if the node matches the requirement and determine if
# any missing dependencies. It is showing output in table view and also save a log file in /var/tmp/_illumio_pcecheck.log.
# The file can tells more detail after the script has executed.
# For RHEL/CentOS 7 & 8 only.

# Created by: Siew Boon Siong
# Email: siew.boonsiong@gmail.com
# Updated: Jan-28-2021
# Update Feb-21-2022 - Kib to KB and RHEL 8.x


function TARLOGS_CLEANUP() {
    date=$(date '+%Y-%m-%d')
    if [[ "${fail}" == 0 ]]; then
        tar czf ${WorkingDirectory}/${date}_${HOSTNAME}_${OS}_illumioreport_SUCCESS.tgz ${IllumioVENdir} ${IllumioVENdatadir} ${WorkingDirectory}/_illumio_*.log
    else
        tar czf ${WorkingDirectory}/${date}_${HOSTNAME}_${OS}_illumioreport_FAILED.tgz ${IllumioVENdir} ${IllumioVENdatadir} ${WorkingDirectory}/_illumio_*.log
    fi

    rm -rf ${WorkingDirectory}/_illumio_*.log
    # rm -rf ${WorkingDirectory}/RhelCentos-VEN-Install-v1.13.sh
} &>/dev/null

# Generic statements for workload info
function NODE_INFO_STATEMENT() {
    echo "$(date) Server Hostname: ${HOSTNAME}" >>${LogFile}
    echo "$(date) Server IP(s): ${IPAdd}" >>${LogFile}

    osVersion=('RedHat' 'CentOS')
    for i in ${osVersion[*]}; do
        [[ "${OS}" == "${i}" ]] && echo "$(date) Server OS: ${OSoutput} is supported" >>${LogFile}
    done

    if [[ "${OS}" =~ ^(RedHat|CentOS)$ ]] && [[ "$(arch)" != 'x86_64' ]]; then
        echo "$(date) Non 64-bit OS is not supported" >>${LogFile}
        arch_status='Fail'
    elif [[ "${OS}" =~ ^(RedHat|CentOS)$ ]] && [[ "$(arch)" == 'x86_64' ]]; then
        #echo "$(date) $(arch) is supported" >> ${LogFile}
        arch_status='Pass'
    fi
}

function MENU_CHOICE() {
    if [[ "${choose}" == '5' ]]; then
        break
        exit 1
    fi
    RHEL_CENTOS_OS_CHECK
    CPU_CHECK
    RAM_CHECK
    VARIOUS_CHECK
    TABLE_OUTPUT
}

function SUB_MENU() {
    line=$(for i in $(seq 1 61); do printf "="; done)
    clear
    echo $line
    echo "                Select Node Type"
    echo $line
    CoreNode="Core Node?"
    DataNode="Data Node?"
    PreviousMenu="Back to Main Menu"

    PS3="""
## RE-Enter an option for check or Enter "4" to quit :
${txtblu}1${txtrst} -> Core Node?     | ${txtblu}2${txtrst} -> Data Node? | ${txtblu}3${txtrst} -> Back to Main Menu
${txtblu}4${txtrst} -> ${txtred}EXIT${txtrst}

"""

    select choice in "$CoreNode" "$DataNode" "$PreviousMenu" EXIT; do
        case $choice in
        $CoreNode)
            echo -e "\nCore Node Check\n"
            subchoose='1'
            MENU_CHOICE
            ;;
        $DataNode)
            echo -e "\nData Node Check\n"
            subchoose='2'
            MENU_CHOICE
            ;;
        $PreviousMenu)
            echo -e "\nBack to Previous Menu]=[]\n"
            choose='3'
            MAIN_MENU
            ;;
        EXIT)
            echo "Bye!"
            exit 1
            # choose='5'
            # MENU_CHOICE
            ;;
        *)
            echo -e "\n==> Select an option"
            ;;
        esac
    done
}

function MAIN_MENU() {
    line=$(for i in $(seq 1 61); do printf "="; done)
    clear
    echo $line
    echo "                Select Menu for PCE model"
    echo $line
    SNC="SNC (Single Node Cluster)"
    MNC1="2x2 MNC (Multi Node Cluster for < 2500 VENs)"
    MNC2="2x2 MNC (Multi Node Cluster for < 10000 VENs)"
    MNC3="4x2 MNC (High Spec Multi Node Cluster for < 25000 VENs)"

    PS3="""
Enter an option:
"""

    select choice in "$SNC" "$MNC1" "$MNC2" "$MNC3" EXIT; do
        case $choice in
        $SNC)
            echo -e "\nSNC (Single Node Cluster)\n"
            choose='1'
            MENU_CHOICE
            ;;
        $MNC1)
            echo -e "\n2x2 MNC (Multi Node Cluster for < 2500 VENs)\n"
            choose='2'
            #   MENU_CHOICE
            SUB_MENU
            ;;
        $MNC2)
            echo -e "\n2x2 MNC (Multi Node Cluster for < 10000 VENs)\n"
            choose='3'
            #   MENU_CHOICE
            SUB_MENU
            ;;
        $MNC3)
            echo -e "\n4x2 MNC (High Spec Multi Node Cluster for < 25000 VENs)\n"
            choose='4'
            #   MENU_CHOICE
            SUB_MENU
            ;;
        EXIT)
            echo "Bye!"
            exit 1
            # choose='5'
            # MENU_CHOICE
            ;;
        *)
            echo -e "\n==> Select an option"
            ;;
        esac

        PS3="Press Enter to continue ....."
        PS3="""
## RE-Enter an option for check or Enter "5" to quit :
${txtblu}1${txtrst} -> SNC     | ${txtblu}2${txtrst} -> 2x2 Low MNC | ${txtblu}3${txtrst} -> 2x2 High MNC
${txtblu}4${txtrst} -> 4x2 MNC | ${txtblu}5${txtrst} -> ${txtred}EXIT${txtrst}

"""
    done
}

function RHEL_CENTOS_OS_CHECK() {
    # Check if the OS supported. If it is not supported or out of the list, job exit.
    echo "$(date) Checking Operating System..." >>${LogFile}
    # The length of output of /etc/redhat-release differents in each OS , setting 2 variable and trying to catch all.
    OSrelease=NotFound
    if [[ "${OSrelease}" == 'NotFound' ]]; then
        redHatRelease=/etc/redhat-release
        OSoutput=$(cat /etc/redhat-release)
        if test -f "${redHatRelease}"; then
            if grep -q 'Red Hat' ${redHatRelease}; then
                echo "$(date) RedHat Detected." >>${LogFile}
                OS='RedHat'
                OSrelease=$(cat ${redHatRelease} | rev | cut -d'(' -f 2 | rev | awk 'NF>1{print $NF}' | cut -d$'.' -f1)
                OSminor=$(cat ${redHatRelease} | rev | cut -d'(' -f 2 | rev | awk 'NF>1{print $NF}' | cut -d$'.' -f2)
            fi
            if grep -q 'CentOS' ${redHatRelease}; then
                echo "$(date) CentOS Detected." >>${LogFile}
                OS='CentOS'
                OSrelease=$(cat ${redHatRelease} | rev | cut -d'(' -f 2 | rev | awk 'NF>1{print $NF}' | cut -d$'.' -f1)
                OSminor=$(cat ${redHatRelease} | rev | cut -d'(' -f 2 | rev | awk 'NF>1{print $NF}' | cut -d$'.' -f2)
            fi
        fi
    fi

    if [[ "${OSrelease}" == '6' ]] && [[ "${OSminor}" =~ ^(8|9|10)$ ]]; then
        IPAdd=$(hostname -I)
        os_status=${txtred}'Fail  '${txtrst}
        echo "$(date) ${txtred}ATTENTION${txtrst}: Node OS: version ${OSrelease} has already EOL-ed by CentOS or Red Hat in Nov-30, 2020." | tee ${LogFile}
        echo "$(date) ${txtred}NOTIFY${txtrst}: Node OS: ${OSoutput} is NOT recommended to be used for PCE setup." | tee ${LogFile}
        exit 1
    elif [[ "${OSrelease}" == '7' ]] && [[ "${OSminor}" -gt 3 ]]; then
        IPAdd=$(hostname -I)
        os_status=${txtwht}'Pass  '${txtrst}
        NODE_INFO_STATEMENT
    elif [[ "${OSrelease}" == '8' ]] && [[ "${OSminor}" -lt 6 ]]; then
        IPAdd=$(hostname -I)
        os_status=${txtwht}'Pass  '${txtrst}
        NODE_INFO_STATEMENT
    else
        echo "$(date) ERROR: Node OS: ${OSoutput} is not supported. Exit." | tee ${LogFile}
        os_status=${txtred}'Fail  '${txtrst}
        TARLOGS_CLEANUP
        exit 1
    fi

    kernelVer=$(uname -r)
    hypervisorType=$(grep "Hypervisor detected" /var/log/dmesg | cut -d$':' -f2 | awk '{$1=$1};1')
    if [[ "${OSrelease}" == '7' ]]; then
        distro=$(head -1 /etc/os-release | cut -d$'"' -f2 | cut -d$' ' -f1 2>/dev/null)
        if [[ "${OSrelease}" =~ ^(7)$ ]] && [[ "${distro}" =~ ^(CentOS|Oracle|Red)$ ]]; then
            distro_status=${txtwht}'Pass  '${txtrst}
            if [[ "${distro}" == 'Red' ]]; then
                distro='Red Hat'
            fi
        else
            echo "$(date) ERROR: OS Distro: ${OSoutput} is not supported" >>${LogFile}
            distro_status=${txtred}'Fail  '${txtrst}
            TARLOGS_CLEANUP
            exit 1
        fi
    fi
}&>/dev/null

function CPU_CHECK() {
    cpuCheck=$(getconf _NPROCESSORS_ONLN)
    cpuModel=$(grep "model name" /proc/cpuinfo | uniq -c | cut -d$':' -f2 | awk '{$1=$1};1')
    if [[ "${choose}" == '1' ]] && [[ "${cpuCheck}" -ge 2 ]]; then
        #echo "$(date) This node has ${cpuCheck} CPUs" >> ${LogFile}
        cpu_status=${txtwht}'Pass  '${txtrst}
    elif [[ "${choose}" == '2' ]] && [[ "${cpuCheck}" -ge 4 ]]; then
        #echo "$(date) This node has ${cpuCheck} CPUs" >> ${LogFile}
        cpu_status=${txtwht}'Pass  '${txtrst}
    elif [[ "${choose}" == '3' ]] && [[ "${cpuCheck}" -ge 16 ]]; then
        #echo "$(date) This node has ${cpuCheck} CPUs" >> ${LogFile}
        cpu_status=${txtwht}'Pass  '${txtrst}
    elif [[ "${choose}" == '4' ]] && [[ "${cpuCheck}" -ge 16 ]]; then
        #echo "$(date) This node has ${cpuCheck} CPUs" >> ${LogFile}
        cpu_status=${txtwht}'Pass  '${txtrst}
    else
        echo "$(date) ERROR: This node has insufficient number of ${cpuCheck} CPUs" >>${LogFile}
        cpu_status=${txtred}'Fail  '${txtrst}
    fi
}

function RAM_CHECK() {
    ramCheck=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    ramCheck=$((${ramCheck} / 1000000 ))
    if [[ "${choose}" == '1' ]] && [[ "${ramCheck}" -ge 8 ]]; then
        #echo "$(date) This node has ${ramCheck}GB RAM" >> ${LogFile}
        ram_status=${txtwht}'Pass  '${txtrst}
    elif [[ "${choose}" == '2' ]] && [[ "${ramCheck}" -ge 32 ]]; then
        #echo "$(date) This node has ${ramCheck}GB RAM" >> ${LogFile}
        ram_status=${txtwht}'Pass  '${txtrst}
    elif [[ "${choose}" == '3' ]] && [[ "${ramCheck}" -ge 64 ]]; then
        #echo "$(date) This node has ${ramCheck}GB RAM" >> ${LogFile}
        ram_status=${txtwht}'Pass  '${txtrst}
        if [[ "${ramCheck}" -lt 128 ]]; then
            echo "$(date) NOTIFY: For this type of PCE setup, it is recommended at least 128GB RAM per node" >>${LogFile}
        fi
    elif [[ "${choose}" == '4' ]] && [[ "${ramCheck}" -ge 128 ]]; then
        #echo "$(date) This node has ${ramCheck}GB RAM" >> ${LogFile}
        ram_status=${txtwht}'Pass  '${txtrst}
    else
        echo "$(date) ERROR: This node has insufficient number of ${ramCheck} RAM" >>${LogFile}
        ram_status=${txtred}'Fail  '${txtrst}
    fi
}

function VARIOUS_CHECK() {
    # locale check
    localeConf='/etc/locale.conf'
    localeCheck=$(grep -r -E -i "(en_US.UTF-8|en_GB.UTF-8)" ${localeConf} | cut -d$'=' -f2)
    if grep -q -r -E -i "(en_US.UTF-8|en_GB.UTF-8)" ${localeConf}; then
        locale_status=${txtwht}'Pass  '${txtrst}
    else
        echo "$(date) ERROR: Locale set is incorrect." >>${LogFile}
        locale_status=${txtred}'Fail  '${txtrst}
    fi

    # Illumio specific systemd for RHEL/CentOS 7 or 8
    if [[ "${OSrelease}" == '7|8' ]]; then
        systemdConf='/etc/systemd/system/illumio-pce.service.d/override.conf'
        systemdCore=$(grep "LimitCORE.*0" ${systemdConf} | xargs)
        if grep -q "LimitCORE.*0" ${systemdConf}; then
            s100_status=${txtwht}'Pass  '${txtrst}
        else
            echo "$(date) ERROR: LimitCORE setting in ${systemdConf} is missing or incorrect." >>${LogFile}
            s100_status=${txtred}'Fail  '${txtrst}
        fi

        systemdNOFILE=$(grep "LimitNOFILE.*65535" ${systemdConf} | xargs)
        if grep -q "LimitNOFILE.*65535" ${systemdConf}; then
            s101_status=${txtwht}'Pass  '${txtrst}
        else
            echo "$(date) ERROR: LimitNOFILE setting in ${systemdConf} is missing or incorrect." >>${LogFile}
            s101_status=${txtred}'Fail  '${txtrst}
        fi

        systemdNPROC=$(grep "LimitNPROC.*65535" ${systemdConf} | xargs)
        if grep -q "LimitNPROC.*65535" ${systemdConf}; then
            s102_status=${txtwht}'Pass  '${txtrst}
        else
            echo "$(date) ERROR: LimitNPROC setting in ${systemdConf} is missing or incorrect." >>${LogFile}
            s102_status=${txtred}'Fail  '${txtrst}
        fi
    fi

    # OS kernel parameters for Core node and SNC
    kernelConf='/etc/sysctl.d/99-illumio.conf'
    fsFileMax=$(grep "fs.file-max.*=.*2000000" ${kernelConf} | xargs)
    if grep -q "fs.file-max.*=.*2000000" ${kernelConf}; then
        k1_status=${txtwht}'Pass  '${txtrst}
    else
        echo "$(date) ERROR: fs.file-max Kernel setting in ${kernelConf} is missing or incorrect." >>${LogFile}
        k1_status=${txtred}'Fail  '${txtrst}
    fi

    netCoreSoMax=$(grep "net.core.somaxconn.*=.*16384" ${kernelConf} | xargs)
    if grep -q "net.core.somaxconn.*=.*16384" ${kernelConf}; then
        k2_status=${txtwht}'Pass  '${txtrst}
    else
        echo "$(date) ERROR: net.core.somaxconn Kernel setting in ${kernelConf} is missing or incorrect." >>${LogFile}
        k2_status=${txtred}'Fail  '${txtrst}
    fi

    netConntrackMax=$(grep "net.nf_conntrack_max.*=.*1048576" ${kernelConf} | xargs)
    if grep -q "net.nf_conntrack_max.*=.*1048576" ${kernelConf}; then
        k3_status=${txtwht}'Pass  '${txtrst}
    else
        echo "$(date) ERROR: net.nf_conntrack_max Kernel setting in ${kernelConf} is missing or incorrect." >>${LogFile}
        k3_status=${txtred}'Fail  '${txtrst}
    fi

    # OS kernel parameters for Data node and SNC
    kernelShMax=$(grep "kernel.shmmax.*=.*60000000" ${kernelConf} | xargs)
    if grep -q "kernel.shmmax.*=.*60000000" ${kernelConf}; then
        k4_status=${txtwht}'Pass  '${txtrst}
    else
        echo "$(date) ERROR: kernel.shmmax Kernel setting in ${kernelConf} is missing or incorrect." >>${LogFile}
        k4_status=${txtred}'Fail  '${txtrst}
    fi

    vmOvercommit=$(grep "vm.overcommit_memory.*=.*1" ${kernelConf} | xargs)
    if grep -q "vm.overcommit_memory.*=.*1" ${kernelConf}; then
        k5_status=${txtwht}'Pass  '${txtrst}
    else
        echo "$(date) ERROR: vm.overcommit_memory Kernel setting in ${kernelConf} is missing or incorrect." >>${LogFile}
        k5_status=${txtred}'Fail  '${txtrst}
    fi

    # tune the kernel conntrack module
    kModule='/sys/module/nf_conntrack/parameters/hashsize'
    pip2=$(grep -s "262144" ${kModule} | xargs)
    if grep -q -s "262144" ${kModule}; then
        pip2_status=${txtwht}'Pass  '${txtrst}
    else
        echo "$(date) ERROR: 262144 value is missing in ${kModule}." >>${LogFile}
        pip2_status=${txtred}'Fail  '${txtrst}
    fi

    kModule2='/etc/modprobe.d/illumio.conf'
    pip4=$(grep -s "options nf_conntrack hashsize=262144" ${kModule2} | xargs)
    if grep -q -s "options nf_conntrack hashsize=262144" ${kModule2}; then
        pip4_status=${txtwht}'Pass  '${txtrst}
    else
        echo "$(date) ERROR: 'options nf_conntrack hashsize=262144' value is missing in ${kModule2}." >>${LogFile}
        pip4_status=${txtred}'Fail  '${txtrst}
    fi

    # ilo-pipgen requirement
    pip1=$(grep -s "1048576" /proc/sys/net/nf_conntrack_max | xargs)
    if grep -q -s "1048576" /proc/sys/net/nf_conntrack_max; then
        pip1_status=${txtwht}'Pass  '${txtrst}
    else
        echo "$(date) ERROR: 1048576 value in /proc/sys/net/nf_conntrack_max is missing or incorrect." >>${LogFile}
        pip1_status=${txtred}'Fail  '${txtrst}
    fi

    pip2=$(grep -s "262144" ${kModule} | xargs)
    if grep -q -s "262144" ${kModule}; then
        pip2_status=${txtwht}'Pass  '${txtrst}
    else
        echo "$(date) ERROR: 262144 value is missing in ${kModule}." >>${LogFile}
        pip2_status=${txtred}'Fail  '${txtrst}
    fi

    pip5=$(grep -s "net.nf_conntrack_max=1048576" /etc/sysctl.d/illumio.conf | xargs)
    if grep -q -s "net.nf_conntrack_max=1048576" /etc/sysctl.d/illumio.conf; then
        pip5_status=${txtwht}'Pass  '${txtrst}
    else
        echo "$(date) ERROR: 'net.nf_conntrack_max=1048576' value in /etc/sysctl.d/illumio.conf is missing or incorrect." >>${LogFile}
        pip5_status=${txtred}'Fail  '${txtrst}
    fi

    # ilo-vpngen requirement
    vpn1=$(grep -s "32767" /proc/sys/net/ipv4/xfrm4_gc_thresh | xargs)
    if grep -q -s "32767" /proc/sys/net/ipv4/xfrm4_gc_thresh; then
        vpn1_status=${txtwht}'Pass  '${txtrst}
    else
        echo "$(date) ERROR: 32767 value in /proc/sys/net/ipv4/xfrm4_gc_thresh." >>${LogFile}
        vpn1_status=${txtred}'Fail  '${txtrst}
    fi

    vpn2=$(grep -s "net.ipv4.xfrm4_gc_thresh=32767" /etc/sysctl.d/illumio.conf | xargs)
    if grep -q -s "net.ipv4.xfrm4_gc_thresh=32767" /etc/sysctl.d/illumio.conf; then
        vpn2_status=${txtwht}'Pass  '${txtrst}
    else
        echo "$(date) ERROR: net.ipv4.xfrm4_gc_thresh=32767 value in /etc/sysctl.d/illumio.conf." >>${LogFile}
        vpn2_status=${txtred}'Fail  '${txtrst}
    fi
} 2>/dev/null

function TABLE_OUTPUT() {
    width="| %-45s | %-45s | %-36s | %-6s |\n"
    width2="| %-55s | %-39s | %-32s | %-6s |\n"
    line="+-----------------------------------------------+-----------------------------------------------+--------------------------------------+--------+"
    line2="+---------------------------------------------------------+-----------------------------------------+----------------------------------+--------+"
    echo -e "\n$line"
    printf "$width" Description Current Required Result
    echo $line
    printf "$width" Hostname ${HOSTNAME} - -
    printf "$width" "IP Address" "${IPAdd}" - -
    printf "$width" "OS Distro" "${distro}" 'RHEL | CentOS | Oracle RHEL' "${distro_status}"
    printf "$width" "OS Version" ${OSrelease}.${OSminor} '6.8~6.10 | 7.4~7.8 | 8.3~8.5' "${os_status}"
    printf "$width" "OS Architecture" $(arch) x86_64 "${arch_status}"
    printf "$teswidtht" "OS Kernel" "${kernelVer}" - -
    printf "$v" "CPU Model" "${cpuModel}" - -
    if [[ "${choose}" == '1' ]]; then
        printf "$width" "Number of CPUs*" ${cpuCheck} '2 for SNC' "${cpu_status}"
        printf "$width" "RAM per Node (GB)" ${ramCheck} '8GB for SNC' "${ram_status}"
    elif [[ "${choose}" == '2' ]]; then
        printf "$width" "Number of CPUs" ${cpuCheck} '4 for 2x2 (Low)' "${cpu_status}"
        printf "$width" "RAM per Node (GB)" ${ramCheck} '32GB for 2x2 (Low)' "${ram_status}"
    elif [[ "${choose}" == '3' ]]; then
        printf "$width" "Number of CPUs" ${cpuCheck} '16 for 2x2 (High)' "${cpu_status}"
        printf "$width" "RAM per Node (GB)" ${ramCheck} '64GB - 128GB for 2x2 (High)' "${ram_status}"
    elif [[ "${choose}" == '4' ]]; then
        printf "$width" "Number of CPUs" ${cpuCheck} '16 for 4x2' "${cpu_status}"
        printf "$width" "RAM per Node (GB)" ${ramCheck} '128GB for 4x2' "${ram_status}"
    fi
    printf "$width" "Hypervisor Type" "${hypervisorType}" - -
    printf "$width" "Locale Set" "${localeCheck}" 'en_US.UTF-8 | en_GB.UTF-8' "${locale_status}"
    echo $line
    echo '* Please also check if the CPU core is at least Intel® Xeon(R) CPU E5-2695 v4 at 2.10GHz or equivalent.'
    echo ''
    echo ''

    # for CentOS/RHEL 7/8 systemd
    if [[ "${OSrelease}" -gt 7 ]] && ([[ "${choose}" == '1' ]] || [[ "${subchoose}" == '1' ]] || [[ "${subchoose}" == '2' ]]); then
        echo "The following kernel settings are required for both ${txtblu}Core & Data Nodes, also for SNC${txtrst}:"
        echo "${txtred}ATTENTION!${txtrst} You will need to create /etc/systemd/system/illumio-pce.service.d/override.conf file after PCE RPM installed."
        echo "* For CentOS 7.x or RHEL 7.x with systemd."
        echo "* Remember reload the daemon: ${txtred}systemctl daemon-reload${txtrst}, then ${txtred}systemctl restart illumio-pce.service${txtrst}"
        echo "* Verify it is in effect: ${txtred}sudo -u ilo-pce systemctl show illumio-pce.service | egrep \"LimitCORE|LimitNPROC|LimitNOFILE\"${txtrst}"
        echo "* If the environment prefers init.d rather than systemd, plese check the Illumio manual on how to set init.d value for PCE."
        echo $line2
        printf "$width2" Illumio-specific Existing Required Result
        echo $line2
        printf "$width2" "${systemdConf}" "${systemdCore}" 'LimitCORE=0' "${s100_status}"
        printf "$width2" "${systemdConf}" "${systemdNOFILE}" 'LimitNOFILE=65535' "${s101_status}"
        printf "$width2" "${systemdConf}" "${systemdNPROC}" 'LimitNPROC=65535' "${s102_status}"
        echo $line2
    fi
    echo ''
    echo ''

    # kernel setting for Core node and SNC
    if [[ "${choose}" == '1' ]] || [[ "${subchoose}" == '1' ]]; then
        echo "The following kernel settings are required for ${txtblu}Core Nodes and SNC only${txtrst}:"
        echo "If your settings are greater than these, you do not need to lower them."
        echo "* Remember to apply the change: ${txtred}sysctl -p /etc/sysctl.d/99-illumio.conf${txtrst}"
        echo $line
        printf "$width" File Existing Required Result
        echo $line
        printf "$width" "${kernelConf}" "${fsFileMax}" 'fs.file-max = 2000000' "${k1_status}"
        printf "$width" "${kernelConf}" "${netCoreSoMax}" 'net.core.somaxconn = 16384' "${k2_status}"
        printf "$width" "${kernelConf}" "${netConntrackMax}" 'net.nf_conntrack_max = 1048576' "${k3_status}"
        echo $line
    fi
    echo ''
    echo ''

    # kernel setting for Data node and SNC
    if [[ "${choose}" == '1' ]] || [[ "${subchoose}" == '2' ]]; then
        echo "The following kernel settings are required for ${txtblu}Data Nodes and SNC only${txtrst}:"
        echo "If your settings are greater than these, you do not need to lower them."
        echo "* Remember to apply the change: ${txtred}sysctl -p /etc/sysctl.d/99-illumio.conf${txtrst}"
        echo $line
        printf "$width" File Existing Required Result
        echo $line
        printf "$width" "${kernelConf}" "${fsFileMax}" 'fs.file-max = 2000000' "${k1_status}"
        printf "$width" "${kernelConf}" "${kernelShMax}" 'kernel.shmax = 60000000' "${k4_status}"
        printf "$width" "${kernelConf}" "${vmOvercommit}" 'vm.overcommit_memory = 1' "${k5_status}"
        echo $line
    fi
    echo ''
    echo ''

    # kernel setting for Core node and SNC
    if [[ "${choose}" == '1' ]] || [[ "${subchoose}" == '1' ]]; then
        echo "The following kernel conntrack modules are required for ${txtblu}Core Nodes and SNC only${txtrst}:"
        echo "If your settings are greater than these, you do not need to lower them."
        echo "* Remember to enable first: ${txtred}modprobe nf_conntrack${txtrst}"
        echo $line
        printf "$width" File Existing Required Result
        echo $line
        printf "$width" "${kModule}" "${pip2}" '262144 (for immediate effect)' "${pip2_status}"
        printf "$width" "${kModule2}" "${pip4}" 'options nf_conntrack hashsize=262144' "${pip4_status}"
        echo $line
    fi
    echo ''
    echo ''

    # ilo-pipgen setting
    echo "The following kernel settings are required for ilo-pipgen service ${txtred}AFTER${txtrst} PCE RPM has installed:"
    echo $line
    printf "$width" File Existing Required Result
    echo $line
    printf "$width" "/proc/sys/net/nf_conntrack_max" "${pip1}" '1048576 (for immediate effect)' "${pip1_status}"
    printf "$width" "/sys/module/nf_conntrack/parameters/hashsize" "${pip2}" '262144 (for immediate effect)' "${pip2_status}"
    printf "$width" "/etc/sysctl.d/illumio.conf" "${pip5}" 'net.nf_conntrack_max=1048576' "${pip5_status}"
    printf "$width" "${kModule}" "${pip4}" 'options nf_conntrack hashsize=262144' "${pip4_status}"
    echo $line

    echo ''
    echo ''
    # ilo-vpngen setting
    if [[ "${subchoose}" == '1' ]] || [[ "${subchoose}" == '2' ]]; then
        echo "The following kernel settings are required for ilo-vpngen service ${txtred}AFTER${txtrst} PCE RPM has installed:"
        echo $line
        printf "$width" File Existing Required Result
        echo $line
        printf "$width" "/proc/sys/net/ipv4/xfrm4_gc_thresh" "${vpn1}" '32767' "${vpn1_status}"
        printf "$width" "/etc/sysctl.d/illumio.conf" "${vpn2}" 'net.ipv4.xfrm4_gc_thresh=32767' "${vpn2_status}"
        echo $line
    fi
    echo ''
    PCE_PACKAGES
    DISK_SPACE_CHECK
}

function PCE_PACKAGES() {
    width="| %-24s | %-45s | %-6s |\n"
    line="+--------------------------+-----------------------------------------------+--------+"
    echo "Require packages/dependencies for PCE:"
    echo $line
    printf "$width" 'Required Package' Discovered Result
    echo $line
    if [[ "${OS}" == 'RedHat' || "${OS}" == 'CentOS' ]] && [[ "${OSrelease}" -gt 7 ]]; then
        rpmPackageCheck=('bash' 'bzip2' 'chkconfig' 'coreutils' 'findutils' 'curl' 'gawk' 'grep' 'initscripts' 'gzip' 'logrotate' 'net-tools' 'procps-ng' 'sed' 'shadow-utils' 'tar' 'util-linux' 'zlib' 'ntp' 'bind-utils' 'libnfnetlink' 'glibc' 'ncurses')
        for package in ${rpmPackageCheck[*]}; do
            packageOut=$(rpm -q ${package} | grep x86)
            if rpm -q ${package} | grep x86 >/dev/null 2>&1; then
                package_status='Pass  '
                printf "$width" "${package}" "${packageOut}" ${txtwht}"${package_status}"${txtrst}
            else
                echo "$(date) ERROR: ${package} package is not installed." >>${LogFile}
                package_status='Fail  '
                printf "$width" "${package}" "${packageOut}" ${txtred}"${package_status}"${txtrst}
            fi
        done

        rpmPackageCheck=('procps' 'ca-certificates' 'rsyslog')
        for package in ${rpmPackageCheck[*]}; do
            packageOut=$(rpm -qa | grep ${package})
            if rpm -qa | grep ${package} >/dev/null 2>&1; then
                package_status='Pass  '
                printf "$width" "${package}" "${packageOut}" ${txtwht}"${package_status}"${txtrst}
            else
                echo "$(date) ERROR: ${package} package is not installed." >>${LogFile}
                package_status='Fail  '
                printf "$width" "${package}" "${packageOut}" ${txtred}"${package_status}"${txtrst}
            fi
        done
    fi
    echo $line
    echo -e "\n$line"
    printf "$width" 'Required FIPS Package' Discovered Result
    echo $line
    if [[ "${OS}" == 'RedHat' || "${OS}" == 'CentOS' ]] && [[ "${OSrelease}" -gt 7 ]]; then
        rpmFileCheck=('libssl.so.10' 'libcrypto.so.10')
        for package in ${rpmFileCheck[*]}; do
            packageOut=$(find /usr/lib64/ -iname ${package})
            if [[ -f /usr/lib64/${package} || -f /usr/bin/${package} || -f /bin/${package} || -f /sbin/${package} || -f /usr/sbin/${package} ]] >/dev/null 2>&1; then
                package_status='Pass  '
                printf "$width" "${package}" "${packageOut}" ${txtwht}"${package_status}"${txtrst}
            else
                package_status='Fail  '
                echo "$(date) ERROR: ${package} package is not installed." >>${LogFile}
                printf "$width" "${package}" "${packageOut}" ${txtred}"${package_status}"${txtrst}
            fi
        done
    fi
    echo $line
    echo -e "\n$line"
    printf "$width" 'Required Libraries' Discovered Result
    echo $line
    if [[ "${OS}" == 'RedHat' || "${OS}" == 'CentOS' ]] && [[ "${OSrelease}" -gt 7 ]]; then
        rpmPackageCheck=('glibc' 'libgcc' 'libstdc++' 'libuuid' 'ncurses-libs' 'openssl' 'zlib')
        for package in ${rpmPackageCheck[*]}; do
            packageOut=$(rpm -q ${package} | grep x86)
            if rpm -q ${package} | grep x86 >/dev/null 2>&1; then
                package_status='Pass  '
                printf "$width" "${package}" "${packageOut}" ${txtwht}"${package_status}"${txtrst}
            else
                echo "$(date) ERROR: ${package} library not found." >>${LogFile}
                package_status='Fail  '
                printf "$width" "${package}" "${packageOut}" ${txtred}"${package_status}"${txtrst}
            fi
        done
    fi
    echo $line
    echo -e "\n$line"
    printf "$width" 'Required Libraries' Discovered Result
    echo $line
    if [[ "${OS}" == 'RedHat' || "${OS}" == 'CentOS' ]] && [[ ${OSrelease} -gt 7 ]]; then
        rpmFileCheck=('libreadline.so.6' 'libselinux.so.1')
        for package in ${rpmFileCheck[*]}; do
            packageOut=$(find /usr/lib64/ -iname ${package})
            if [[ -f /usr/lib64/${package} || -f /usr/bin/${package} || -f /bin/${package} || -f /sbin/${package} || -f /usr/sbin/${package} ]] >/dev/null 2>&1; then
                package_status='Pass  '
                printf "$width" "${package}" "${packageOut}" ${txtwht}"${package_status}"${txtrst}
            else
                package_status='Fail  '
                echo "$(date) ERROR: ${package} library not found." >>${LogFile}
                printf "$width" "${package}" "${packageOut}" ${txtred}"${package_status}"${txtrst}
            fi
        done
    fi
    echo $line
    echo ''
    echo "NOTE: ilo-pipgen is required for all types of PCE"
    echo $line
    printf "$width" 'ilo-pipgen Package' Discovered Result
    echo $line
    rpmPackageCheck=('iptables-services')
    packageOut=$(rpm -q iptables-services)
    if rpm -q ${rpmPackageCheck} >/dev/null 2>&1; then
        package_status='Pass  '
        printf "$width" "${rpmPackageCheck}" "${packageOut}" ${txtwht}"${package_status}"${txtrst}
    else
        echo "$(date) ERROR: ${rpmPackageCheck} package is not installed." >>${LogFile}
        package_status='Fail  '
        printf "$width" "${rpmPackageCheck}" "${packageOut}" ${txtred}"${package_status}"${txtrst}
    fi
    echo $line
    if [[ "${subchoose}" == '1' ]] || [[ "${subchoose}" == '2' ]]; then
        echo ''
        echo "NOTE: ilo-vpngen is not required for SNC"
        echo $line
        printf "$width" 'ilo-vpngen Package' Discovered Result
        echo $line
        if [[ "${OS}" == 'RedHat' || "${OS}" == 'CentOS' ]] && [[ "${OSrelease}" -gt 7 ]]; then
            rpmPackageCheck=('libreswan' 'ldns' 'libevent' 'nss' 'nss-tools' 'unbound-libs' 'libpcap' 'nspr' 'nss-softokn' 'nss-softokn-freebl' 'nss-sysinit' 'nss-util')
            for package in ${rpmPackageCheck[*]}; do
                packageOut=$(rpm -q ${package} | grep x86)
                if rpm -q ${package} | grep x86 >/dev/null 2>&1; then
                    package_status='Pass  '
                    printf "$width" "${package}" "${packageOut}" ${txtwht}"${package_status}"${txtrst}
                else
                    echo "$(date) ERROR: ${package} package is not installed." >>${LogFile}
                    package_status='Fail  '
                    printf "$width" "${package}" "${packageOut}" ${txtred}"${package_status}"${txtrst}
                fi
            done
        fi
        echo $line
        echo ''
    fi
}

function DISK_SPACE_CHECK() {
    echo ''
    echo ''
    echo "$(date) Existing Disk Status:" | tee -a ${LogFile}
    echo '================================' | tee -a ${LogFile}
    df -kh | tee -a ${LogFile}
    echo ''
    echo '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>' | tee -a ${LogFile}
    lsblk | tee -a ${LogFile}
    echo ''
    echo '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>' | tee -a ${LogFile}
    lsblk -d -o name,rota | tee -a ${LogFile}
    echo ''
    echo '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>' | tee -a ${LogFile}
    cat /proc/scsi/scsi | tee -a ${LogFile}
    echo ''
    echo '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>' | tee -a ${LogFile}
    dmesg | grep -i -e scsi -e ata | tee -a ${LogFile}
}

#############################################################################

WorkingDirectory='/var/tmp'
LogFile='/var/tmp/_illumio_pcecheck.log'
txtwht=$(tput setaf 7)
txtblu=$(tput setaf 2)
txtred=$(tput setaf 1)
txtrst=$(tput sgr0)

# Job begin
# Check if the executer is root user or not before proceed
if [[ "$(id -u)" != "0" ]]; then
    echo "ERROR: The script must be running as root, aborting."
    exit 1
else
    cd $WorkingDirectory
    touch ${LogFile} && chmod 644 ${LogFile}
    echo "$(date) PCE Node Check begin..." >>${LogFile}
    # Define an initial fail bit, this decides whether the script installs the PCE or not in the later stage.
    fail=0
fi

MAIN_MENU
