from scapy.all import *
import sys
import pyudev # type: ignore
import netifaces
import subprocess
import psutil
import time
import re
import os
from plyer import notification
from threading import Thread
import pandas
from colorama import init, Fore
init()
GREEN = Fore.GREEN
RED   = Fore.RED
BLUE   = Fore.BLUE
RESET = Fore.RESET

class Sources:
    def __init__(self):
        self.eviltwin_data = []
        self.arp_table = {}
        
    def get_interface_menufacturer_name(self,interface):

        context = pyudev.Context()
        for device in context.list_devices(subsystem='net'):
            if device.sys_name.startswith(interface):
                try:
                    manufacturer = str(device.get('ID_VENDOR_FROM_DATABASE')) + " " + str(device.get('ID_MODEL_FROM_DATABASE'))
                    return manufacturer
                except KeyError:
                    return ""
                
    def get_ip_address(self,interface):
        try:
            addresses = netifaces.ifaddresses(interface)
            ip_address = addresses[netifaces.AF_INET][0]['addr']
            return ip_address
        except KeyError:
            return None
    def get_mac_address(self,interface):
        try:
            addresses = netifaces.ifaddresses(interface)
            ip_address = addresses[netifaces.AF_LINK][0]['addr']
            return ip_address
        except KeyError:
            return None
    
    def get_dev_path(self,wireless_interface):
        try:
            output = subprocess.check_output(f"udevadm info /sys/class/net/{wireless_interface}", shell=True).decode()
            devpath = re.search(r'DEVPATH=(.*)', output).group(1).split("/")
            devpath.pop(-1)
            devpath = "/".join(devpath)
            return devpath
        except subprocess.CalledProcessError:
            return f"udevadm command failed for {wireless_interface}"
        except AttributeError:
            return f"Device path not found for {wireless_interface}"
        
    def get_ifindex(self, wireless_interface):
        try:
            output = subprocess.check_output(f'cat /sys/class/net/{wireless_interface}/ifindex', shell=True).decode().strip()
            return output
        except subprocess.CalledProcessError:
            return f"Interface {wireless_interface} not found or command failed"
    
    def sent_notifications(self,title,message):
        notification.notify(title=title,message=message,timeout=20,toast=False)

    def listinterfaces(self):
        list_of_interfaces = []
        self.i = 0
        self.addrs = psutil.net_if_addrs()
        os.system("clear")
        print(" Network Interfaces:- ")
        for interfaces in self.addrs.keys():
            print(str(self.i) + ". " +interfaces + "   \t|\t" + self.get_interface_menufacturer_name(interfaces))
            self.i+=1
            list_of_interfaces.append(interfaces)

        return list_of_interfaces
    
    def selectadapter(self):
        list_of_interface = self.listinterfaces()
        interface_input = input(f"{GREEN}Select wireless interface by typing 0-{str(self.i-1)}: -->{RESET} ")
        try:
            wireless_interface = list_of_interface[int(interface_input)]
            print(f"\n\n{GREEN}[++]Selected interface is {wireless_interface}.{RESET}")
            return wireless_interface
        except (IndexError, ValueError) as e:
            print(f"{RED}[--] Please Select correct index number for wireless adaptor or Select Correct WIreless Adaptor...{RESET}")
            return None
    
    def checkmode(self, wireless_interface):
        try:
            output = subprocess.check_output(f'iwconfig {wireless_interface}', shell=True).decode()
            mode = re.search(r'Mode:(\w+)', output).group(1)
            return mode
        except Exception as e:
            return str(e)
        
    def change_interface_channel(self,network_interface,channel):
        print(f"{BLUE}\n[-][-] Changing Channel of deauth wireless interface to the channel of target network.{RESET}")
        result = subprocess.run(f"iwconfig {network_interface} channel {channel}", shell=True, capture_output=True, text=True)
        print(result.stderr)

    def kill_process(self,name):
        result = subprocess.run(f"killall {name}", shell=True, capture_output=True, text=True)
        print(f"{RED}[-]Killing All Process with name {name}{RESET}")
        print(result.stderr)

    def select_network(self,wirelessinterface):
        target_network = {"ssid":"","bssid":"","channel":"","encryption":""}
        networks_info = self.list_networks(wirelessinterface)
        os.system("clear")
        print("\n\n")
        network_number = 0
        for networks_names in networks_info.index:
            print(f"{BLUE}{network_number}. {networks_info.loc[networks_names,'SSID']}\t( BSSID={networks_names} , Channel={networks_info.loc[networks_names,'Channel']} , Encryption={networks_info.loc[networks_names,'Crypto']} , Signal Strenght={networks_info.loc[networks_names,'dBm_Signal']} ){RESET}")
            network_number += 1
        target = input(f" Select the target network from above list by typing index number as 0-{network_number-1} --> ")
        bssid = networks_info.index[int(target)]
        ssid = networks_info.loc[bssid,'SSID']
        channel = networks_info.loc[bssid,'Channel']
        crypto = networks_info.loc[bssid,'Crypto']
        target_network["ssid"] = ssid
        target_network["bssid"] = bssid
        target_network["channel"] = channel
        target_network["encryption"] = crypto

        print(f"{GREEN}\n Target Network:  SSID={target_network['ssid']}   BSSID={target_network['bssid']}   Channel={target_network['channel']}{RESET}\n")
        return target_network




    def list_networks(self,wireless_interface):
        scantime = input(f"\n{GREEN}[+]Select the time in second for scanning wireless networks. Recommanded: '20' ---> {RESET}")
        if scantime != "":
            scantime = int(scantime)
        else:
            scantime = 20
        if self.checkmode(wireless_interface) == "Managed":
            print(f"{RED}[--]Your wireless adapter for Listing wireless networks is in Managed mode, it should be in Monitor mode. Changing Mode to Monitor.... {RESET}")
            from changemode import ChangeMode
            wireless_interface = ChangeMode().changetomonitormode(wireless_interface)
            networks_info = self.show_wireles_networks(wireless_interface,scantime)

        else:
            networks_info = self.show_wireles_networks(wireless_interface,scantime)
        
        return networks_info
    
            
    def show_wireles_networks(self,wirelessinterface,timeout):
        search_time = timeout
        current_time = time.time()
        networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
        networks.set_index("BSSID", inplace=True)

        def callback(packet):
            if packet.haslayer(Dot11Beacon): # type: ignore
                bssid = packet[Dot11].addr2 # type: ignore
                ssid = packet[Dot11Elt].info.decode() # type: ignore
                try:
                    dbm_signal = packet.dBm_AntSignal
                except:
                    dbm_signal = "N/A"
                stats = packet[Dot11Beacon].network_stats() # type: ignore
                channel = stats.get("channel")
                crypto = stats.get("crypto")
                networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)
    


        def print_all():
            while True:
                os.system("clear")
                print(networks)
                time.sleep(0.5)
                if time.time() > current_time+search_time:
                    break
        

        def change_channel():
            channels = list(range(1, 15)) + list(range(36, 165, 4))
            ch_index = 0
            while True:
                ch = channels[ch_index]
                result = subprocess.run(f"iwconfig {interface} channel {ch}", shell=True, capture_output=True, text=True)
                if 'Error for wireless request "Set Frequency" (8B04) :' in result.stderr:
                    pass
                ch_index = (ch_index + 1) % len(channels)
                time.sleep(0.5)
                if time.time() > current_time+search_time:
                    break
                

        interface = wirelessinterface
        printer = Thread(target=print_all)
        printer.daemon = True
        printer.start()
        channel_changer = Thread(target=change_channel)
        channel_changer.daemon = True
        channel_changer.start()
        t = AsyncSniffer(prn=callback, iface=interface)
        t.start()
        time.sleep(search_time)
        t.stop()

        return networks




    def capture_deauth_packets(self,interface,bssid):
        self.deauth_packets_no = 0
        self.deauth_started_time = None
        self.deauth_last_packet_time = None
        self.deauth_data = []
        def handle_packet(packet):
            if packet.haslayer(Dot11): # type: ignore
                if packet.type == 0 and packet.subtype == 12:
                    self.deauth_packets_no+=1
                    if self.deauth_packets_no > 15 and self.deauth_packets_no < 25:
                        self.deauth_started_time = time.time()
                    if self.deauth_started_time and str(packet.addr2).lower() == bssid:
                        if time.time() - self.deauth_started_time >= 5:
                            self.deauth_data = ["1",packet.addr1]
                            self.deauth_last_packet_time = time.time()
                else:
                    if self.deauth_last_packet_time:
                        if time.time() - self.deauth_last_packet_time >= 10:
                            self.deauth_data = ["0"]
                    
                        

        try:
            print(f"[*] Checking for DDOS and EVIL TWIN Attacks... Press Ctrl+C to stop.")
            sniff(iface=interface, prn=handle_packet, store=0)
        except KeyboardInterrupt:
            print("[*] Stopping capture.")
            sys.exit(0)

    def get_wireles_networks(self,wirelessinterface,timeout):
        search_time = timeout
        current_time = time.time()
        networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
        networks.set_index("BSSID", inplace=True)

        def callback(packet):
            if packet.haslayer(Dot11Beacon): # type: ignore
                bssid = packet[Dot11].addr2 # type: ignore
                ssid = packet[Dot11Elt].info.decode() # type: ignore
                try:
                    dbm_signal = packet.dBm_AntSignal
                except:
                    dbm_signal = "N/A"
                stats = packet[Dot11Beacon].network_stats() # type: ignore
                channel = stats.get("channel")
                crypto = stats.get("crypto")
                networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)
    


        def print_all():
            while True:
                time.sleep(0.5)
                if time.time() > current_time+search_time:
                    break
        

        def change_channel():
            channels = list(range(1, 15)) + list(range(36, 165, 4))
            ch_index = 0
            while True:
                ch = channels[ch_index]
                result = subprocess.run(f"iwconfig {interface} channel {ch}", shell=True, capture_output=True, text=True)
                if 'Error for wireless request "Set Frequency" (8B04) :' in result.stderr:
                    pass
                ch_index = (ch_index + 1) % len(channels)
                time.sleep(0.5)
                if time.time() > current_time+search_time:
                    break
                

        interface = wirelessinterface
        printer = Thread(target=print_all)
        printer.daemon = True
        printer.start()
        channel_changer = Thread(target=change_channel)
        channel_changer.daemon = True
        channel_changer.start()
        t = AsyncSniffer(prn=callback, iface=interface)
        t.start()
        time.sleep(search_time)
        t.stop()

        return networks
    
    def check_for_network(self,wirelessinterface,target_ssid):
        detected_evil = 0
        networks_info = self.get_wireles_networks(wirelessinterface,15)
        ssid_groups = networks_info.groupby("SSID")
        for ssid, group in ssid_groups:
            if len(group) > 1:
                if ssid == target_ssid:
                    bssids = group.index.unique()
                    if len(bssids) > 1:
                        self.eviltwin_data = ["1","2",bssids.tolist()]
                        detected_evil = 1
                    else:
                        self.eviltwin_data = ["1","1", bssids.tolist()[0]]
                        detected_evil = 1
        if detected_evil == 0:
            self.eviltwin_data = []

    def capture_mac_address_in_network(self,wireless_interface):
        def scan_network(ip_range):
            arp = ARP(pdst=ip_range) # type: ignore
            ether = Ether(dst="ff:ff:ff:ff:ff:ff") # type: ignore
            packet = ether / arp
            result = srp(packet,iface=wireless_interface, timeout=20, verbose=0)[0]
            devices = {}
            
            for sent, received in result:
                devices[received.psrc] = str(received.hwsrc).lower()
            
            return devices
        try:
            ip_address = self.get_ip_address(wireless_interface)
            ip_base = str(ip_address).split(".")
            ip = f"{ip_base[0]}.{ip_base[1]}.{ip_base[2]}.1"
            network = f"{ip}/24"
            devices = scan_network(network)
            devices[ip_address] = str(self.get_mac_address(wireless_interface)).lower()
            return devices
        except Exception:
            return {}
    
    def arp_table_update_and_spoof_detect(self,gateway_ip,gateway_mac,wireless_interface):
        self.arp_table["gateway_ip"] = gateway_ip
        self.arp_table[gateway_ip] = gateway_mac
        check_again = 0
        while True:
            captured_table = self.capture_mac_address_in_network(wireless_interface)
            for captured_ip in list(captured_table.keys()):
                if captured_ip in self.arp_table and str(captured_table[captured_ip]).lower() == str(self.arp_table[captured_ip]).lower():
                    pass
                elif captured_ip in self.arp_table and str(captured_table[captured_ip]).lower() != str(self.arp_table[captured_ip]).lower():
                    if str(captured_table[captured_ip]).lower() in list(self.arp_table.values()):
                        pass
                    elif str(self.arp_table[captured_ip]).lower() in list(captured_table.values()):
                        for ip, mac in captured_table.items():
                            if mac == str(self.arp_table[captured_ip]).lower():
                                if ip != captured_ip:
                                    self.arp_table[captured_ip] = str(captured_table[captured_ip]).lower()
                    else:
                        if check_again == 1:
                            check_again = 0
                            self.arp_table[captured_ip] = str(captured_table[captured_ip]).lower()
                        else:
                            check_again = 1


                else:
                    self.arp_table[captured_ip] = str(captured_table[captured_ip]).lower()
            
            time.sleep(5)
            
    

    def check_arp_reponses(self,wireless_interface):
        self.arp_spoofing_packet_no = 0
        self.arp_spoofing_started = None
        self.arp_spoofing_lastpacket = None
        self.mitm_started = None
        self.arp_spoofing_conflicting_ip = []
        self.print_ips = []
        def arp_display(packet):
            if packet.haslayer(ARP): # type: ignore
                if packet[ARP].op == 2: # type: ignore
                    mac_address =  str(packet[ARP].hwsrc).lower() # type: ignore
                    ip_address = str(packet[ARP].psrc) # type: ignore
                    if ip_address in self.arp_table and mac_address == str(self.arp_table[ip_address]).lower():
                        pass
                    elif ip_address in self.arp_table and mac_address != str(self.arp_table[ip_address]).lower():
                        self.arp_spoofing_packet_no += 1
                        if self.arp_spoofing_packet_no > 3:
                            self.arp_spoofing_lastpacket = time.time()
                            target_mac = self.arp_table[ip_address]
                            if ip_address in self.arp_spoofing_conflicting_ip:
                                pass
                            else:
                                self.arp_spoofing_conflicting_ip.append(ip_address)
                            if self.arp_spoofing_started == None or str(ip_address) not in self.print_ips:
                                if len(self.arp_spoofing_conflicting_ip) == 1:
                                    message = f"[Alert]--> Arp spoofing Detected: Attacker Mac = {mac_address} | Target IP = {ip_address} | Target Mac = {target_mac}"
                                    print(message)
                                    self.sent_notifications("Arp Spoofing Detected",message)
                                    self.arp_spoofing_started = True
                                else:
                                    if self.arp_table["gateway_ip"] in self.arp_spoofing_conflicting_ip:
                                        if self.arp_table["gateway_ip"] == ip_address:
                                            target_ip = self.arp_spoofing_conflicting_ip[0]
                                            target_mac = self.arp_table[target_ip]
                                        else:
                                            target_ip = ip_address
                                        message = f"[Alert]--> MITM Detected: Attacker Mac = {mac_address} | Attacker is developing connection between Router and Target IP = {target_ip} Target Mac = {target_mac}"
                                        print(message)
                                        self.sent_notifications("MITM Detected",message)
                                    else:
                                        first_target_ip = self.arp_spoofing_conflicting_ip[0]
                                        second_target_ip = self.arp_spoofing_conflicting_ip[1]
                                        first_target_mac = self.arp_table[first_target_ip]
                                        second_target_mac = self.arp_table[second_target_ip]
                                        message = f"[Alert]--> MITM Detected: Attacker Mac = {mac_address} | Attacker is developing connection between First Target = {first_target_ip}'{first_target_mac}' and Second Target = {second_target_ip}'{second_target_mac}'"
                                        print(message)
                                        self.sent_notifications("MITM Detected",message)
                                self.print_ips.append(ip_address)
                            
            if self.arp_spoofing_started == True:
                if time.time() - self.arp_spoofing_lastpacket > 10:
                    message = "[Alert]--> Arp spoofing and MITM attack is stopped ...."
                    print(message)
                    self.arp_spoofing_packet_no = 0
                    self.sent_notifications("Arp Spoofing Or MITM Stopped",message)
                    self.arp_spoofing_started = None
                    self.print_ips = []
                    self.arp_spoofing_conflicting_ip = []
                            
        print("[*] Checking for ARP Spoofing or MITM Attacks.. Press CTRL+C to stop...")
        sniff(filter="arp",iface=wireless_interface, prn=arp_display, store=0)
    

        

        
