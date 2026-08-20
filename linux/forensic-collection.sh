#!/bin/bash

# -----------------------------------------------------------------------------
# Require root/elevated privileges before doing anything else.
# Almost every step below (reading /etc/shadow, per-user crontabs, /proc for
# other users, SUID/SGID scans across all mounts, /var/log/audit, etc.)
# silently produces incomplete or misleading results if run as a normal user,
# so fail loudly up front instead of collecting a partial/unreliable snapshot.
# -----------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] This script must be run as root (or via sudo)." >&2
    echo "        Current user: $(id -un) (uid $(id -u))" >&2
    echo "        Re-run as: sudo $0" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# Create a forensic collection directory
# Directory permissions are locked down (700) via umask BEFORE anything is
# written, since /etc/shadow, SSH keys, and shell history will land in here.
# -----------------------------------------------------------------------------
umask 077

HOST=$(hostname -f 2>/dev/null || hostname)
TS=$(date +%F_%H%M)
FORENSICS_DIR="/root/forensics_${HOST}_${TS}"

mkdir -p "${FORENSICS_DIR}"
chmod 700 "${FORENSICS_DIR}"

# -----------------------------------------------------------------------------
# Failure tracking
# Every step that can plausibly fail is run through run_step() so that a
# missing binary or permission error doesn't just scroll past in the log --
# it gets tallied and printed in the final summary.
# -----------------------------------------------------------------------------
FAILCOUNT=0
FAILED_STEPS=()

run_step() {
    local desc="$1"
    shift
    "$@"
    local rc=$?
    if [ ${rc} -ne 0 ]; then
        FAILCOUNT=$((FAILCOUNT + 1))
        FAILED_STEPS+=("${desc} (exit ${rc})")
        echo "[WARN] Step failed: ${desc} (exit ${rc})"
    fi
    return ${rc}
}

# Wraps a tar of a directory with a disk-space pre-check. Skips (and records
# a failure) rather than risking filling the disk mid-collection.
tar_with_space_check() {
    local desc="$1" src="$2" dest="$3"
    local need avail required

    need=$(du -sk "${src}" 2>/dev/null | awk '{print $1}')
    [ -z "${need}" ] && need=0

    avail=$(df -k --output=avail "$(dirname "${dest}")" 2>/dev/null | tail -1 | tr -d ' ')
    [ -z "${avail}" ] && avail=0

    # Require source size plus a 100MB safety margin (tar.gz is usually
    # smaller than the source, so this is intentionally conservative).
    required=$((need + 102400))

    if [ "${avail}" -lt "${required}" ]; then
        echo "[WARN] Skipping ${desc}: insufficient disk space (avail ${avail}KB, need ~${required}KB for ${src})"
        FAILCOUNT=$((FAILCOUNT + 1))
        FAILED_STEPS+=("${desc}: skipped, insufficient disk space (avail ${avail}KB, need ~${required}KB)")
        return 1
    fi

    tar --acls --xattrs -czpf "${dest}" "${src}"
    local rc=$?
    if [ ${rc} -ne 0 ]; then
        FAILCOUNT=$((FAILCOUNT + 1))
        FAILED_STEPS+=("${desc} (tar exit ${rc})")
        echo "[WARN] ${desc} failed (tar exit ${rc})"
    fi
    return ${rc}
}

# -----------------------------------------------------------------------------
# Log script execution
# -----------------------------------------------------------------------------
SCRIPT_START=$(date +%s)

LOGFILE="${FORENSICS_DIR}/collection.log"

exec > >(awk '{ print strftime("[%Y-%m-%d %H:%M:%S]"), $0; fflush(); }' \
    | tee -a "${LOGFILE}")
exec 2>&1

echo "========================================================="
echo " Forensic Collection Started"
echo "========================================================="
echo "Host      : ${HOST}"
echo "Directory : ${FORENSICS_DIR}"
echo "Started   : $(date)"
echo

# -----------------------------------------------------------------------------
# Detect OS family (cheap, needed by later steps, doesn't disturb volatile state)
# -----------------------------------------------------------------------------
OS_FAMILY="unknown"

if [ -f /etc/os-release ]; then

    . /etc/os-release

    case "${ID} ${ID_LIKE:-}" in
        *debian*|*ubuntu*|*mint*)
            OS_FAMILY="debian"
            ;;
        *rhel*|*fedora*|*centos*|*rocky*|*almalinux*|*oracle*|*ol*)
            OS_FAMILY="redhat"
            ;;
    esac

fi

echo "Detected OS family: ${OS_FAMILY}" \
    > "${FORENSICS_DIR}/os_family.txt"

# -----------------------------------------------------------------------------
# Save the forensic script itself
# Later you'll know exactly what was collected.
# -----------------------------------------------------------------------------
cp "$0" "${FORENSICS_DIR}/collection_script.sh" 2>/dev/null
sha256sum "$0" \
    > "${FORENSICS_DIR}/collection_script.sha256" 2>/dev/null

# =============================================================================
# PHASE 1: MOST VOLATILE EVIDENCE FIRST
# Network state, active sessions, processes, and open files can change or
# disappear within seconds -- these are captured before anything slower
# (log archiving, package inventories, etc).
# =============================================================================

# -----------------------------------------------------------------------------
# Current logged in users and active sessions
# -----------------------------------------------------------------------------
echo "[INFO] (volatile) Collecting active user sessions"
run_step "active_sessions (w)" bash -c \
    "w > '${FORENSICS_DIR}/active_sessions.txt' 2>&1"

run_step "who" bash -c \
    "who > '${FORENSICS_DIR}/who.txt' 2>&1"

# -----------------------------------------------------------------------------
# All current network connections
# Useful for identifying active attacker sessions and beaconing
# -----------------------------------------------------------------------------
echo "[INFO] (volatile) Collecting network connections"
run_step "network_connections (ss -tunap)" bash -c \
    "ss -tunap > '${FORENSICS_DIR}/network_connections.txt' 2>&1"

run_step "network_connections_extended (ss -tunape)" bash -c \
    "ss -tunape > '${FORENSICS_DIR}/network_connections_extended.txt' 2>&1"

run_step "listening_ports (ss -tulpn)" bash -c \
    "ss -tulpn > '${FORENSICS_DIR}/listening_ports.txt' 2>&1"

# -----------------------------------------------------------------------------
# ARP cache
# -----------------------------------------------------------------------------
echo "[INFO] (volatile) Collecting ARP cache"
run_step "arp_cache" bash -c \
    "arp -an > '${FORENSICS_DIR}/arp_cache.txt' 2>&1"

run_step "neighbor_cache" bash -c \
    "ip neigh > '${FORENSICS_DIR}/neighbor_cache.txt' 2>&1"

# -----------------------------------------------------------------------------
# Full running processes
# Useful for identifying malware, reverse shells and persistence
# -----------------------------------------------------------------------------
echo "[INFO] (volatile) Collecting process info"
run_step "processes (ps -efww)" bash -c \
    "ps -efww > '${FORENSICS_DIR}/processes.txt' 2>&1"

run_step "process_tree (ps auxfww)" bash -c \
    "ps auxfww > '${FORENSICS_DIR}/process_tree.txt' 2>&1"

# -----------------------------------------------------------------------------
# Open files
# Useful for detecting deleted malware still running, suspicious outbound
# connections, hidden files
# -----------------------------------------------------------------------------
echo "[INFO] (volatile) Collecting open files"
if command -v lsof >/dev/null 2>&1; then
    run_step "open_files (lsof)" bash -c \
        "lsof -nP > '${FORENSICS_DIR}/open_files.txt' 2>&1"
fi

# -----------------------------------------------------------------------------
# Loaded kernel modules
# Useful for detecting rootkits and low-level persistence
# -----------------------------------------------------------------------------
echo "[INFO] (volatile) Collecting loaded kernel modules"
run_step "loaded_kernel_modules (lsmod)" bash -c \
    "lsmod > '${FORENSICS_DIR}/loaded_kernel_modules.txt' 2>&1"

# -----------------------------------------------------------------------------
# Cross-check against /proc directly, since ps/ss/lsmod are exactly the
# binaries a rootkit is likely to have trojaned. Also flags processes
# running from a deleted binary (a classic fileless-persistence indicator).
# -----------------------------------------------------------------------------
echo "[INFO] (volatile) Collecting raw /proc snapshot"
{
    for p in /proc/[0-9]*; do
        pid=$(basename "$p")
        exe=$(readlink "$p/exe" 2>/dev/null)
        cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
        echo "PID ${pid} | EXE: ${exe} | CMD: ${cmd}"
    done
} > "${FORENSICS_DIR}/proc_snapshot.txt" 2>/dev/null

grep -i "(deleted)" "${FORENSICS_DIR}/proc_snapshot.txt" \
    > "${FORENSICS_DIR}/proc_deleted_exe_processes.txt" 2>/dev/null

# -----------------------------------------------------------------------------
# Environment variables (of this shell -- best-effort, still fairly volatile)
# -----------------------------------------------------------------------------
echo "[INFO] (volatile) Collecting env variables"
run_step "environment_variables" bash -c \
    "printenv > '${FORENSICS_DIR}/environment_variables.txt' 2>&1"

# -----------------------------------------------------------------------------
# Mounted filesystems / disk usage
# Also builds the list of local mountpoints used later for the -xdev loop.
# -----------------------------------------------------------------------------
echo "[INFO] Collecting filesystem mounts and disk info"
run_step "mounts" bash -c \
    "mount > '${FORENSICS_DIR}/mounts.txt' 2>&1"

run_step "filesystem_usage" bash -c \
    "df -h > '${FORENSICS_DIR}/filesystem_usage.txt' 2>&1"

run_step "block_devices" bash -c \
    "lsblk -a > '${FORENSICS_DIR}/block_devices.txt' 2>&1"

# Build a list of local (non-pseudo, non-network) mounted filesystems so that
# SUID/SGID/authorized_keys searches below aren't silently scoped to just "/".
PSEUDO_FS_REGEX='^(proc|sysfs|devtmpfs|tmpfs|devpts|cgroup|cgroup2|pstore|bpf|autofs|mqueue|debugfs|tracefs|securityfs|configfs|fusectl|hugetlbfs|rpc_pipefs|nsfs|binfmt_misc|nfs|nfs4|cifs|smb|smb3)$'

mapfile -t LOCAL_MOUNTS < <(
    findmnt -rn -o TARGET,FSTYPE 2>/dev/null \
        | awk -v re="${PSEUDO_FS_REGEX}" '$2 !~ re {print $1}' \
        | sort -u
)

if [ ${#LOCAL_MOUNTS[@]} -eq 0 ]; then
    LOCAL_MOUNTS=("/")
fi

{
    echo "Local mountpoints scanned for SUID/SGID/authorized_keys below:"
    printf '%s\n' "${LOCAL_MOUNTS[@]}"
} > "${FORENSICS_DIR}/scanned_mountpoints.txt"

# =============================================================================
# PHASE 2: LESS VOLATILE EVIDENCE
# =============================================================================

# -----------------------------------------------------------------------------
# IP/dns configuration
# -----------------------------------------------------------------------------
echo "[INFO] Collecting IP info"
run_step "ip_addr" bash -c \
    "ip addr > '${FORENSICS_DIR}/ip_addr.txt' 2>&1"

run_step "ip_route" bash -c \
    "ip route > '${FORENSICS_DIR}/ip_route.txt' 2>&1"

run_step "hostnamectl" bash -c \
    "hostnamectl > '${FORENSICS_DIR}/hostnamectl.txt' 2>&1"

run_step "hosts_file" bash -c \
    "cat /etc/hosts > '${FORENSICS_DIR}/hosts_file.txt' 2>&1"

run_step "resolv_conf" bash -c \
    "cat /etc/resolv.conf > '${FORENSICS_DIR}/resolv_conf.txt' 2>&1"

# -----------------------------------------------------------------------------
# Firewall configuration
# -----------------------------------------------------------------------------
echo "[INFO] Collecting firewall config"
if command -v firewall-cmd >/dev/null 2>&1; then
    run_step "firewalld_config" bash -c \
        "firewall-cmd --list-all-zones > '${FORENSICS_DIR}/firewalld_config.txt' 2>&1"
fi

if command -v nft >/dev/null 2>&1; then
    run_step "nftables_rules" bash -c \
        "nft list ruleset > '${FORENSICS_DIR}/nftables_rules.txt' 2>&1"
fi

if command -v iptables-save >/dev/null 2>&1; then
    run_step "iptables_rules" bash -c \
        "iptables-save > '${FORENSICS_DIR}/iptables_rules.txt' 2>&1"
fi

# -----------------------------------------------------------------------------
# Login / reboot history
# -----------------------------------------------------------------------------
echo "[INFO] Collecting login history"
run_step "last_logins" bash -c \
    "last > '${FORENSICS_DIR}/last_logins.txt' 2>&1"

run_step "lastlog" bash -c \
    "lastlog > '${FORENSICS_DIR}/lastlog.txt' 2>&1"

run_step "reboot_history" bash -c \
    "last reboot > '${FORENSICS_DIR}/reboot_history.txt' 2>&1"

# -----------------------------------------------------------------------------
# Collect shell history
# -----------------------------------------------------------------------------
echo "[INFO] Collecting shell history"
mkdir -p "${FORENSICS_DIR}/shell_history"

cp /root/.bash_history \
    "${FORENSICS_DIR}/shell_history/root_bash_history" \
    2>/dev/null

find /home -name ".bash_history" \
    -exec cp --parents {} "${FORENSICS_DIR}/shell_history/" \; \
    2>/dev/null

find /home -name ".zsh_history" \
    -exec cp --parents {} "${FORENSICS_DIR}/shell_history/" \; \
    2>/dev/null

find /root /home \
    -name ".mysql_history" \
    -exec cp --parents {} "${FORENSICS_DIR}/shell_history/" \; \
    2>/dev/null

find /root /home \
    -name ".psql_history" \
    -exec cp --parents {} "${FORENSICS_DIR}/shell_history/" \; \
    2>/dev/null

# -----------------------------------------------------------------------------
# Save current local account databases
# -----------------------------------------------------------------------------
echo "[INFO] Collecting account databases and sudo info"
cp /etc/passwd "${FORENSICS_DIR}/passwd"
cp /etc/shadow "${FORENSICS_DIR}/shadow"
cp /etc/group "${FORENSICS_DIR}/group"

{
    echo "==== /etc/passwd ===="
    stat /etc/passwd

    echo
    echo "==== /etc/shadow ===="
    stat /etc/shadow

    echo
    echo "==== /etc/group ===="
    stat /etc/group
} > "${FORENSICS_DIR}/account_file_stats.txt"

getent passwd \
    > "${FORENSICS_DIR}/all_local_users.txt"

{
    echo "==== wheel group ===="
    getent group wheel 2>/dev/null

    echo
    echo "==== sudo group ===="
    getent group sudo 2>/dev/null

} > "${FORENSICS_DIR}/privileged_groups.txt"

# -----------------------------------------------------------------------------
# Collect sudo configuration
# -----------------------------------------------------------------------------
mkdir -p "${FORENSICS_DIR}/sudo"

cp /etc/sudoers \
    "${FORENSICS_DIR}/sudo/" 2>/dev/null

cp -r /etc/sudoers.d \
    "${FORENSICS_DIR}/sudo/" 2>/dev/null

# -----------------------------------------------------------------------------
# Save directory timestamps for user home directories
# -----------------------------------------------------------------------------
echo "[INFO] Collecting home directory filestamps"
run_step "home_directory_listing" bash -c \
    "ls -ld /home/* > '${FORENSICS_DIR}/home_directory_listing.txt' 2>&1"

# -----------------------------------------------------------------------------
# SSH configuration
# -----------------------------------------------------------------------------
echo "[INFO] Collecting SSH config"
mkdir -p "${FORENSICS_DIR}/ssh"

cp /etc/ssh/sshd_config \
    "${FORENSICS_DIR}/ssh/" 2>/dev/null

cp -r /etc/ssh/sshd_config.d \
    "${FORENSICS_DIR}/ssh/" 2>/dev/null

# -----------------------------------------------------------------------------
# Collect all authorized_keys files, and SUID/SGID binaries, across every
# local mountpoint (not just "/"), using the LOCAL_MOUNTS list built above.
# -----------------------------------------------------------------------------
echo "[INFO] Collecting SSH authorized_keys and SUID/SGID binaries (all local mounts)"
mkdir -p "${FORENSICS_DIR}/sshkeys"
: > "${FORENSICS_DIR}/suid_binaries.txt"
: > "${FORENSICS_DIR}/sgid_binaries.txt"

for mnt in "${LOCAL_MOUNTS[@]}"; do
    find "${mnt}" -xdev -name authorized_keys \
        -exec cp --parents {} "${FORENSICS_DIR}/sshkeys/" \; \
        2>/dev/null

    find "${mnt}" -xdev -perm -4000 \
        >> "${FORENSICS_DIR}/suid_binaries.txt" 2>/dev/null

    find "${mnt}" -xdev -perm -2000 \
        >> "${FORENSICS_DIR}/sgid_binaries.txt" 2>/dev/null
done

sort -u -o "${FORENSICS_DIR}/suid_binaries.txt" "${FORENSICS_DIR}/suid_binaries.txt"
sort -u -o "${FORENSICS_DIR}/sgid_binaries.txt" "${FORENSICS_DIR}/sgid_binaries.txt"

# -----------------------------------------------------------------------------
# Cron: read the spool directories directly (raw files, preserving
# timestamps/ownership) rather than relying solely on `crontab -l`, which
# normalizes output and can miss malformed/hand-edited entries.
# `crontab -l` is still collected per-user as a readable cross-reference.
# -----------------------------------------------------------------------------
echo "[INFO] Collecting cron info"
mkdir -p "${FORENSICS_DIR}/cron"

for spool in /var/spool/cron/crontabs /var/spool/cron; do
    if [ -d "${spool}" ]; then
        cp -a "${spool}" \
            "${FORENSICS_DIR}/cron/$(basename "${spool}")_raw" 2>/dev/null
        ls -la "${spool}" \
            > "${FORENSICS_DIR}/cron/$(basename "${spool}")_listing.txt" 2>&1
    fi
done

run_step "root_crontab" bash -c \
    "crontab -l > '${FORENSICS_DIR}/root_crontab.txt' 2>&1"

for u in $(cut -f1 -d: /etc/passwd); do
    {
        echo "=================================================="
        echo "USER: ${u}"
        echo "=================================================="
        crontab -u "${u}" -l 2>&1
        echo
    }
done > "${FORENSICS_DIR}/all_user_crontabs.txt"

ls -la /etc/cron* \
    > "${FORENSICS_DIR}/etc_cron_listing.txt" 2>&1

echo "[INFO] Collecting systemd timers"
run_step "systemd_timers" bash -c \
    "systemctl list-timers --all > '${FORENSICS_DIR}/systemd_timers.txt' 2>&1"

# -----------------------------------------------------------------------------
# Save enabled/running systemd services
# -----------------------------------------------------------------------------
echo "[INFO] Collecting systemd unit/service info"
run_step "enabled_services" bash -c \
    "systemctl list-unit-files > '${FORENSICS_DIR}/${HOST}_enabled_services.txt' 2>&1"

run_step "running_services" bash -c \
    "systemctl list-units --type=service --all > '${FORENSICS_DIR}/running_services.txt' 2>&1"

# -----------------------------------------------------------------------------
# Server metadata
# -----------------------------------------------------------------------------
echo "[INFO] Collecting server metadata"
{
    echo "===== hostname ====="
    hostname -f 2>/dev/null || hostname

    echo
    echo "===== os-release ====="
    cat /etc/os-release

    echo
    echo "===== kernel ====="
    uname -a

    echo
    echo "===== uptime ====="
    uptime

    echo
    echo "===== date ====="
    date

} > "${FORENSICS_DIR}/serverinfo.txt"

# -----------------------------------------------------------------------------
# Installed packages
# -----------------------------------------------------------------------------
echo "[INFO] Collecting package information"

if [ "${OS_FAMILY}" = "redhat" ]; then

    run_step "installed_packages (rpm)" bash -c \
        "rpm -qa --last > '${FORENSICS_DIR}/installed_packages.txt' 2>&1"

    head -200 "${FORENSICS_DIR}/installed_packages.txt" \
        > "${FORENSICS_DIR}/recently_installed_packages.txt" 2>&1

    run_step "package_history (dnf/yum)" bash -c \
        "dnf history > '${FORENSICS_DIR}/package_history.txt' 2>&1 || yum history > '${FORENSICS_DIR}/package_history.txt' 2>&1"

elif [ "${OS_FAMILY}" = "debian" ]; then

    run_step "installed_packages (dpkg)" bash -c \
        "dpkg-query -W > '${FORENSICS_DIR}/installed_packages.txt' 2>&1"

    grep " install " /var/log/dpkg.log* \
        > "${FORENSICS_DIR}/recently_installed_packages.txt" \
        2>/dev/null

    zcat -f /var/log/apt/history.log* \
        > "${FORENSICS_DIR}/package_history.txt" 2>/dev/null

fi

# -----------------------------------------------------------------------------
# Recently modified files -- both mtime (content/data changed) and ctime
# (metadata/permissions/ownership changed, or mtime deliberately backdated
# with e.g. `touch -r`). Checking both catches more tampering.
# -----------------------------------------------------------------------------
echo "[INFO] Collecting recent file changes (mtime + ctime)"
find /root -type f -mtime -30 \
    > "${FORENSICS_DIR}/root_recent_changes_mtime.txt" 2>/dev/null
find /root -type f -ctime -30 \
    > "${FORENSICS_DIR}/root_recent_changes_ctime.txt" 2>/dev/null

find /etc -type f -mtime -30 \
    > "${FORENSICS_DIR}/etc_recent_changes_mtime.txt" 2>/dev/null
find /etc -type f -ctime -30 \
    > "${FORENSICS_DIR}/etc_recent_changes_ctime.txt" 2>/dev/null

find /usr/local -type f -mtime -30 \
    > "${FORENSICS_DIR}/usr_local_recent_changes_mtime.txt" 2>/dev/null
find /usr/local -type f -ctime -30 \
    > "${FORENSICS_DIR}/usr_local_recent_changes_ctime.txt" 2>/dev/null

# -----------------------------------------------------------------------------
# Docker collection
# -----------------------------------------------------------------------------
echo "[INFO] Collecting docker information"
if command -v docker >/dev/null 2>&1; then

    mkdir -p "${FORENSICS_DIR}/docker"

    run_step "docker_version" bash -c \
        "docker version > '${FORENSICS_DIR}/docker/docker_version.txt' 2>&1"

    run_step "docker_info" bash -c \
        "docker info > '${FORENSICS_DIR}/docker/docker_info.txt' 2>&1"

    run_step "docker_ps" bash -c \
        "docker ps -a > '${FORENSICS_DIR}/docker/docker_ps.txt' 2>&1"

    run_step "docker_ps_full" bash -c \
        "docker ps --no-trunc > '${FORENSICS_DIR}/docker/docker_ps_full.txt' 2>&1"

    run_step "docker_images" bash -c \
        "docker images > '${FORENSICS_DIR}/docker/docker_images.txt' 2>&1"

    run_step "docker_volumes" bash -c \
        "docker volume ls > '${FORENSICS_DIR}/docker/docker_volumes.txt' 2>&1"

    run_step "docker_networks" bash -c \
        "docker network ls > '${FORENSICS_DIR}/docker/docker_networks.txt' 2>&1"

    # Flatten to a single space-separated line. docker ps -aq returns one ID
    # per line, and an unquoted multi-line expansion embedded into a bash -c
    # string gets split into separate commands (each ID after the first is
    # then run as its own "command not found").
    CONTAINERS=$(docker ps -aq | tr '\n' ' ')

    if [ -n "${CONTAINERS// /}" ]; then

        run_step "docker_inspect" bash -c \
            "docker inspect ${CONTAINERS} > '${FORENSICS_DIR}/docker/docker_inspect.json' 2>&1"

        for c in ${CONTAINERS}; do
            run_step "docker_logs_${c}" bash -c \
                "docker logs '${c}' > '${FORENSICS_DIR}/docker/${c}_logs.txt' 2>&1"
        done

    fi

else

    echo "Docker not installed." \
        > "${FORENSICS_DIR}/docker_not_installed.txt"

fi

# -----------------------------------------------------------------------------
# Save /var/log/ (with a disk-space check first, since this can be large)
# -----------------------------------------------------------------------------
echo "[INFO] Saving /var/log"
tar_with_space_check "varlog_tar" /var/log \
    "${FORENSICS_DIR}/${HOST}_varlog.tar.gz"

if [ -f /var/log/audit/audit.log ]; then
    cp /var/log/audit/audit.log* \
        "${FORENSICS_DIR}/" 2>/dev/null
fi

echo "[INFO] Collecting audit information"

if [ -f /var/log/secure ]; then
    cp /var/log/secure* \
        "${FORENSICS_DIR}/" 2>/dev/null
fi

if [ -f /var/log/auth.log ]; then
    cp /var/log/auth.log* \
        "${FORENSICS_DIR}/" 2>/dev/null
fi

if command -v auditctl >/dev/null 2>&1; then
    run_step "audit_rules" bash -c \
        "auditctl -l > '${FORENSICS_DIR}/audit_rules.txt' 2>&1"
fi

# -----------------------------------------------------------------------------
# Export the full systemd journal (with a disk-space check on the binary tar)
# -----------------------------------------------------------------------------
echo "[INFO] Collecting journal logs"
run_step "journalctl_full" bash -c \
    "journalctl --no-pager -o short-iso > '${FORENSICS_DIR}/${HOST}_journalctl_full.log' 2>&1"

if [ -d /var/log/journal ]; then
    tar_with_space_check "journal_binary_tar" /var/log/journal \
        "${FORENSICS_DIR}/journal_binary.tar.gz"
fi

# -----------------------------------------------------------------------------
# Archive /etc (with a disk-space check first)
# -----------------------------------------------------------------------------
tar_with_space_check "etc_backup_tar" /etc \
    "${FORENSICS_DIR}/etc_backup.tar.gz"

# -----------------------------------------------------------------------------
# Document collection completion
# -----------------------------------------------------------------------------
find "${FORENSICS_DIR}" -type f | sort \
    > "${FORENSICS_DIR}/collection_manifest.txt"

SCRIPT_END=$(date +%s)
RUNTIME=$((SCRIPT_END - SCRIPT_START))

# Total size of the collection directory, in GB (base-1024, i.e. GiB),
# with 2 decimal places of precision.
COLLECTION_SIZE_KB=$(du -sk "${FORENSICS_DIR}" 2>/dev/null | awk '{print $1}')
if [ -n "${COLLECTION_SIZE_KB}" ]; then
    COLLECTION_SIZE_GB=$(awk -v kb="${COLLECTION_SIZE_KB}" 'BEGIN { printf "%.2f GB", kb / 1048576 }')
else
    COLLECTION_SIZE_GB="unknown"
fi

echo
echo "========================================================="
echo " Forensic Collection Complete"
echo "========================================================="
echo "Completed : $(date)"
echo "Runtime   : ${RUNTIME} seconds"
echo "Artifacts : ${FORENSICS_DIR}"
echo "Size      : ${COLLECTION_SIZE_GB}"
echo "Failures  : ${FAILCOUNT}"

if [ ${FAILCOUNT} -gt 0 ]; then
    echo
    echo "The following steps failed or were skipped:"
    for step in "${FAILED_STEPS[@]}"; do
        echo "  - ${step}"
    done
fi

