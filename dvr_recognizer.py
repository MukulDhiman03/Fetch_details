import logging

import nmap
import cv2
import netifaces as ni
import telnetlib
import json
import os
import nmap

os.makedirs("images", exist_ok=True)  

# Configure logging
logging.basicConfig(filename='dvr_detection.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

brandName = ""

def save_dvr_details_to_file(ip, channel_no, brand_name, port):
    try:
        with open('ip.json', 'r') as file:
            existing_data = json.load(file)
    except FileNotFoundError:
        existing_data = []

    
    for entry in existing_data:
        if entry['ip'] == ip:
            logging.warning(f"IP {ip} already exists in ip.json. Details not changed.")
            return

   
    new_data = {
        'ip': ip,
        'channel_no': channel_no,
        'brand': brand_name,
        'port': port,
    }
    existing_data.append(new_data)

    # Save updated data back to ip.json
    with open('ip.json', 'w') as file:
        json.dump(existing_data, file, indent=2)
    
    logging.info(f"NVR details saved in ip.json: IP->{ip}, Channel Number->{channel_no}, Brand->{brand_name}")
    
def get_subnet(interface):
    try:
        ip_address = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
        netmask = ni.ifaddresses(interface)[ni.AF_INET][0]['netmask']
    
        # Convert IP address and netmask to binary
        ip_binary = ''.join([bin(int(x)+256)[3:] for x in ip_address.split('.')])
        netmask_binary = ''.join([bin(int(x)+256)[3:] for x in netmask.split('.')])

        # Calculate network address
        network_binary = ''.join([ip_binary[i] if netmask_binary[i] == '1' else '0' for i in range(32)])
        network_address = '.'.join(str(int(network_binary[i:i+8], 2)) for i in range(0, 32, 8))

        subnet_with_mask = f"{network_address}/24"
        return subnet_with_mask

    except (KeyError, ValueError) as e:
        return f"Error: {e}"

def detect_network_interfaces():
    all_interfaces = ni.interfaces()
    ethernet_interfaces = [iface for iface in all_interfaces if ni.AF_LINK in ni.ifaddresses(iface) and iface.startswith('e')]
    wifi_interfaces = [iface for iface in all_interfaces if ni.AF_LINK in ni.ifaddresses(iface) and iface.startswith('w')]

    return ethernet_interfaces, wifi_interfaces



def Hikvision_rtsp(ip, channel, username, password, port):
    url = f"rtsp://{username}:{password}@{ip}:{port}/Streaming/Channels/{channel}01"
    cap = cv2.VideoCapture(url)

    if not cap.isOpened():
        raise Exception("Failed to open RTSP stream.")

    ret, frame = cap.read()
    cap.release()

    if ret:
        return frame
    else:
        raise Exception("Failed to capture frame from RTSP stream.")


def cpplus_rtsp(ip, channel, username, password, port):
    url=f"rtsp://{username}:{password}@{ip}:{port}/cam/realmonitor?channel={channel}&subtype=0"
    cap = cv2.VideoCapture(url)

    if not cap.isOpened():
        raise Exception("Failed to open RTSP stream.")

    ret, frame = cap.read()
    cap.release()

    if ret:
        return frame
    else:
        raise Exception("Failed to capture frame from RTSP stream.")
    

def get_number_of_channels_rtsp(ip, username, password, port,brandName):
    try:
        channel_number = 1
        
        while True:
            try:
                if brandName=="hikvision":
                    image1 = Hikvision_rtsp(ip, channel_number, username, password, port)
                    channel_number += 1
                elif brandName=="cpplus":
                    image1 = cpplus_rtsp(ip, channel_number, username, password, port)
                    channel_number += 1
                cv2.imwrite(f"images/{ip}_{channel_number}.jpg",image1)
            except Exception as e:
                break

        return channel_number - 1

    except Exception as e:
        # print(f"Error for IP {ip}: {e}")
        logging.error(f"Error for IP {ip}: {e}")
        return None


def scan_network():
    ethernet_interfaces, wifi_interfaces = detect_network_interfaces()

    # Initialize an empty list to store potential DVRs
    potential_dvrs = []

    # Scan Ethernet subnets
    for eth_interface in ethernet_interfaces:
        eth_subnet = get_subnet(eth_interface)
        # print(f"Scanning Ethernet subnet: {eth_subnet}")

        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=eth_subnet, arguments='-p 554,1024')

            for host in nm.all_hosts():
                if 'tcp' in nm[host]:
                    if 554 in nm[host]['tcp'] or 1024 in nm[host]['tcp']:
                        potential_dvrs.append(host)

        except Exception as e:
            # print(f"Error scanning Ethernet subnet: {e}")
            logging.error(f"Error for IP {ip}: {e}")

    # Scan Wi-Fi subnets
    for wifi_interface in wifi_interfaces:
        wifi_subnet = get_subnet(wifi_interface)
        # print(f"Scanning Wi-Fi subnet: {wifi_subnet}")

        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=wifi_subnet, arguments='-p 554,1024')

            for host in nm.all_hosts():
                if 'tcp' in nm[host]:
                    if 554 in nm[host]['tcp'] or 1024 in nm[host]['tcp']:
                        potential_dvrs.append(host)

        except Exception as e:
            # print(f"Error scanning Wi-Fi subnet: {e}")
            logging.error(f"Error for IP {ip}: {e}")

    return potential_dvrs

def check_rtsp_port(ip, port):
    try:
        
        with telnetlib.Telnet(ip, port, timeout=5) as tn:
            # print(f"Port {port} is open on {ip}")
            logging.info(f"Port {port} is open on {ip}")
            return port
    except Exception as e:
        # print(f"Port {port} is closed on {ip}")
        logging.error(f"Error for IP {ip}: {e}")
        return None


def dvr_ip_detail(username,password):
    try:
        logging.info("Scanning for subnet")
        potential_dvrs = scan_network()
        logging.info("Scanning done")
        # print(potential_dvrs)
        
        rtsp_ports = [554, 1024]
        open_ports=[]

        if not potential_dvrs:
            logging.warning("No potential DVRs found on the network.")
        else:
            # print(potential_dvrs,"------------------------")
            for ip in potential_dvrs:
                try:
                    for port in rtsp_ports:
                        open_port = check_rtsp_port(ip, port)
                        if open_port is not None:
                            open_ports.append(open_port)
                            
                    logging.info(f"Checking for Hikvision IPs for {ip}")
                    
                    image = Hikvision_rtsp(ip, 1, username, password, open_ports[0])
                    if image is not None:
                        image2 = Hikvision_rtsp(ip, 2, username, password, open_ports[0])
                        if image2 is not None:
                            ip = ip
                            brandName = "hikvision"
                            channel_no = get_number_of_channels_rtsp(ip, username, password, open_ports[0], brandName)
                            save_dvr_details_to_file(ip, channel_no,brandName,open_ports[0])
                            return ip,open_ports[0],brandName
                            
                        if image is not None and image2 is None:
                            ip = ip
                            brandName = "hikvision"
                            channel_no = 1  
                            save_dvr_details_to_file(ip, channel_no, brandName,open_ports[0])
                            return ip,open_ports[0],brandName

                        
                except Exception as e:
                     logging.error(f"Error for IP {ip}: {e}")
                    #  return None,None,None

            for ip in potential_dvrs:
                try:
                    for port in rtsp_ports:
                        open_port = check_rtsp_port(ip, port)
                        if open_port is not None:
                            open_ports.append(open_port)
                    logging.info(f"Checking for CPPlus IPs for {ip}")
                    
                    image = cpplus_rtsp(ip, 1, username, password, open_ports[0])
                    
                    if image is not None:
                        image2 = cpplus_rtsp(ip, 2, username, password, open_ports[0])
                        if image2 is not None:
                            ip = ip
                            brandName = "cpplus"
                            channel_no = get_number_of_channels_rtsp(ip, username, password, open_ports[0], brandName)
                            save_dvr_details_to_file(ip, channel_no, brandName,open_ports[0])
                            return ip,open_ports[0],brandName
                        
                        if image is not None and image2 is None:
                            ip = ip
                            brandName = "cpplus"
                            channel_no = 1
                            save_dvr_details_to_file(ip, channel_no, brandName,open_ports[0])
                            return ip,open_ports[0],brandName
                        
                except Exception as e:
                    logging.error(f"Error for IP {ip}: {e}")
                    # return None,None,None

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
