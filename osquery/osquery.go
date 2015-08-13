package osquery

//CentOsQueries returns a map of pre-built osqueries specific to CentOS
func CentOsQueries() map[string]string {
	cosq := map[string]string{
		//Get rmp_package_files table
		"rpm_package_files": "SELECT * FROM rpm_package_files;",
		//Get rmp_packages table
		"rpm_packages": "SELECT * FROM rpm_packages;",
	}
	return cosq
}

//DebUbOsQueries returns a map of pre-built osqueries specific to Deb/Ub
func DebUbOsQueries() map[string]string {
	dosq := map[string]string{
		//Get apt_sources table
		"apt_sources": "SELECT * FROM apt_sources;",
		//Get rmp_packages table
		"deb_packages": "SELECT * FROM deb_packages;",
	}
	return dosq
}

//GenericOsQueries returns a map of pre-built osqueries that are generic to OS (meaning CentOS/Deb/Ubuntu)
func GenericOsQueries() map[string]string {

	osq := map[string]string{

		//Get kernel information
		"kernel_info": "SELECT * FROM kernel_info;",

		//Get kernel integrity information
		"kernel_integrity": "SELECT * FROM kernel_integrity;",

		//Get kernel modules information
		"kernel_modules": "SELECT * FROM kernel_modules;",

		//Get mount information
		"mounts": "SELECT * FROM mounts;",

		//Get mount information where device_alias is none
		"mounts_device_alias_none": "SELECT * FROM mounts WHERE device_alias = \"none\";",

		//Get block device information
		"block_devices": "SELECT * FROM block_devices;",

		//Get block device information where size is 0
		"block_device_sz0": "SELECT * FROM block_devices WHERE size = \"0\";",

		//Get block device information where vendor is ATA
		"block_device_ata": "SELECT * FROM block_devices WHERE vendor = \"ATA\";",

		//Get acpi tables
		"acpi_tables": "SELECT * FROM acpi_tables;",

		//Get cpuid table
		"cpuid": "SELECT * FROM cpuid;",

		//Get crontab table
		"crontab": "SELECT * FROM crontab;",

		//Get disk_encryption table
		"disk_encryption": "SELECT * FROM disk_encryption;",

		//Get etc_hosts table
		"etc_hosts": "SELECT * FROM etc_hosts;",

		//Get etc_protocols table
		"etc_protocols": "SELECT * FROM etc_protocols;",

		//Get etc_services table
		"etc_services": "SELECT * FROM etc_services;",

		//Get groups table
		"groups": "SELECT * FROM groups;",

		//Get interface_addresses table
		"interface_addresses": "SELECT * FROM etc_interface_addresses;",

		//Get interface_details table
		"interface_details": "SELECT * FROM etc_interface_details;",

		//Get iptables table
		"iptables": "SELECT * FROM etc_iptables;",

		//Get last table which maps processes with users in the system
		"last": "SELECT * FROM etc_last;",

		//Get the list of listening ports
		"listening_ports": "SELECT * FROM listening_ports;",

		//Get the list of logged_in_users
		"logged_in_users": "SELECT * FROM logged_in_users;",

		//Get the current memory map of the machine
		"memory_map": "SELECT * FROM memory_map;",

		//Get the pci_devices mapping from the machine
		"pci_devices": "SELECT * FROM pci_devices;,",

		//Get any passwd changes
		"passwd_changes": "SELECT * FROM passwd_changes;",

		//Get processes
		"processes": "SELECT * FROM processes;",

		//Get processes running from the root
		"processes_root": "SELECT * FROM processes WHERE root = \"\\\";",

		//Get process_envs table
		"process_envs": "SELECT * FROM process_envs;",

		//Get process_memory_map WARNING: THIS QUERY IS HEAVY
		"process_memory_map": "SELECT * FROM process_memory_map;",

		//Get process_open_files table
		"process_open_files": "SELECT * FROM process_open_files;",

		//Get process_open_sockets table
		"process_open_sockets": "SELECT * FROM process_open_sockets;",

		//Get routes table
		"routes": "SELECT * FROM routes;",

		//Get shared memory table
		"shared_memory": "SELECT * FROM shared_memory;",

		//Get shell_history table
		"shell_history": "SELECT * FROM shell_history;",

		//Get all the users
		"users": "SELECT * FROM users;",

		//Get all the user_groups
		"user_groups": "SELECT * FROM user_groups;",

		//Get uptime information
		"uptime": "SELECT * FROM uptime;",

		//Identify if a machine is being used as a relay
		"relay": "SELECT * FROM system_controls WHERE name = 'net.inet.ip.forwarding';",

		//See if there is a MITM in progress
		"mitm": "SELECT * FROM arp_cache;",

		//Retrieves all the files in the target system that are setuid enabled.
		"setuid_enabled": "SELECT * FROM suid_bin;",

		//Quickly scan all process's executable paths to check if the binary
		//still exists on disk. If the binary was replaced (with a newer version for example),
		//on_disk will still equal '0'.
		"q_scan_ps_bin": "SELECT * FROM processes where on_disk = 0;",

		//List the process information for processes listening on TCP/UDP ports.
		"ps_lst_tcp_udp": "SELECT uid, name, path, cmdline, port, address FROM listening_ports l, processes p WHERE l.pid=p.pid;",
	}
	return osq
}
