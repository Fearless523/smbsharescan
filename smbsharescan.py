from impacket import smb
import os
import logging

def scan_smb_shares(ip_list, share_name, max_depth=3):
    logging.basicConfig(filename="scan_log.txt", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    for ip in ip_list:
        try:
            smb_client = smb.SMB(ip, timeout=2)
            smb_client.login("", "")  # Anonymous login
            explore_directory(smb_client, share_name, "/", 0, max_depth)  # Replace "share_name" with the actual share name
            smb_client.close()
            logging.info(f"Successfully connected to SMB share at {ip}")
        except smb.SessionError as e:
            if e.get_error_code() == smb.SMB_STATUS_ACCESS_DENIED:
                logging.warning(f"Access denied to SMB share at {ip}")
            else:
                logging.error(f"Failed to connect to SMB share at {ip}: {e}")
        except smb.NetBIOSError as e:
            logging.error(f"Failed to connect to SMB share at {ip}: {e}")

def explore_directory(smb_client, share_name, directory_path, depth, max_depth):
    if depth > max_depth:
        return
    files = smb_client.listPath(share_name, directory_path)
    for file in files:
        file_path = os.path.join(directory_path, file.get_longname())
        if file.isDirectory():
            explore_directory(smb_client, share_name, file_path, depth + 1, max_depth)
        else:
            # Perform your desired actions here
            file_size = smb_client.getFileSize(share_name, file_path)
            if file_size > 1024:  # Example: Check if file size is greater than 1KB
                print(f"Large file found: {file_path}")

ip_list = ["192.168.0.1", "192.168.0.2", "192.168.0.3"] # Change this
scan_smb_shares(ip_list, "share_name", max_depth=3)
