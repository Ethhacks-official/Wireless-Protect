from sources import Sources
import os
import time
from threading import Thread, Event
import ctypes


class Setup:
    def __init__(self):
        self.sources = Sources()
        self.wireless_interface = ""
        self.wireless_interface2 = ""
        self.target_network = {}

        self.isdeauth_start = 0
        self.isdeauth_stop = 0
        self.iseviltwin_start = 0
        self.iseviltwin_stop = 0
    
    def detect_deauth_attack(self):
        self.deauth_process = Thread(target=self.sources.capture_deauth_packets,args=(self.wireless_interface,str(self.target_network["bssid"]).lower(),))
        self.deauth_process.start()
        check_print = 0
        while True:
            try:
                if self.sources.deauth_data != []:
                    detect_deauth = self.sources.deauth_data
                    if detect_deauth[0] == "1" and check_print == 0:
                        victum_address = detect_deauth[1]
                        self.isdeauth_start = 1
                        if victum_address == "ff:ff:ff:ff:ff:ff":
                            message = f"[Alert] --> Deauth detected for your selected network:  Network-name:{self.target_network["ssid"]} | Network-bssid: {self.target_network["bssid"]} | Attacker is trying to disconnect all client on the network > {victum_address}"
                            print(message)
                            self.sources.sent_notifications("Deauthentication Attack Detected", message)
                        else:
                            message = f"[Alert] --> Deauth detected for your selected network:  Network-name:{self.target_network["ssid"]} | Network-bssid: {self.target_network["bssid"]} | Attacker is trying to disconnect > {victum_address}"
                            print(message)
                            self.sources.sent_notifications("Deauthentication Attack Detected",message)
                        check_print += 1
                    elif detect_deauth[0] == "0" and check_print != 0:
                        if self.iseviltwin_start == 1 or self.iseviltwin_stop == 1:
                            message = "[Alert] --> Deauth attack Stopped. Attacker was trying to do evil twin attack. Change password of all platforms used during this attack...."
                            print(message)
                            self.sources.sent_notifications("Deauthentication Attack Stopped",message)

                        else:
                            message = "[Alert] --> Deauth attack Stopped. May be attacker is trying to capture handshake. Change password of your WIFI network...."
                            print(message)
                            self.sources.sent_notifications("Deauthentication Attack Stopped",message)
                        self.isdeauth_stop = 1
                        self.isdeauth_start = 0
                        check_print = 0 
            except KeyboardInterrupt:
                print("closing..............")
                break

    def check_evil_twin_ddos(self):
        check_print = 0
        evil_withoutDDos = 0
        while True:
            try:
                self.sources.check_for_network(self.wireless_interface,self.target_network["ssid"])
                checker_returned = self.sources.eviltwin_data
                if checker_returned != []:
                    if checker_returned[0] == "1" and (check_print == 0 or (evil_withoutDDos == 1 and self.isdeauth_start == 1)):
                        self.iseviltwin_start = 1
                        self.iseviltwin_stop = 0
                        if checker_returned[1] == "2":
                            attacker_mac = checker_returned[2]
                            if str(self.target_network["bssid"]).lower() in attacker_mac:
                                attacker_mac.remove(str(self.target_network["bssid"]).lower())
                            elif str(self.target_network["bssid"]).upper() in attacker_mac:
                                attacker_mac.remove(str(self.target_network["bssid"]).upper())
                            if self.isdeauth_start == 1:
                                message = f"[Alert] --> Evil Twin attack is detected with DDOS. Following Devices are trying to create evil twin attack with DDOS attack on your network--> {attacker_mac}"
                                print(message)
                                self.sources.sent_notifications("Evil Twin Attack Detected",message)
                                evil_withoutDDos = 0
                            else:
                                message = f"[Alert] --> Evil Twin attack is detected. Following Devices are trying to create exactly similar network but with different bssids --> {attacker_mac}"
                                print(message)
                                self.sources.sent_notifications("Evil Twin Attack Detected",message)
                                evil_withoutDDos = 1
                        elif checker_returned[1] == "1":
                            attacker_mac = checker_returned[2]
                            message = f"[Alert] --> Evil Twin attack is detected. Following Devices are trying to create similar network with similar bssid --> {attacker_mac}"
                            print(message)
                            self.sources.sent_notifications("Evil Twin Attack Detected",message)
                            evil_withoutDDos = 1
                        check_print += 1
                elif self.iseviltwin_start == 1 and checker_returned == [] and check_print != 0:
                    self.iseviltwin_stop = 1
                    self.iseviltwin_start = 0
                    check_print = 0
                    message = f"[Alert] --> Evil Twin attack is stopped.. Change your wifi password and passwords of account you used during this attack...."
                    print(message)
                    self.sources.sent_notifications("Evil Twin Attack Stopped",message)                
            except KeyboardInterrupt:
                break
    

    def start_Detecting_pack1(self):
        os.system("clear")
        self.wireless_interface = self.sources.selectadapter()
        if self.sources.checkmode(self.wireless_interface) == "Managed":
            from changemode import ChangeMode
            self.wireless_interface = ChangeMode().changetomonitormode(self.wireless_interface)
        os.system("clear")
        self.target_network = self.sources.select_network(self.wireless_interface)
        os.system("clear")
        deauth_checker = Thread(target=self.detect_deauth_attack)
        deauth_checker.start()
        self.check_evil_twin_ddos()
        self.terminate_thread(self.deauth_process)
        self.deauth_process.join()
        self.terminate_thread(deauth_checker)
        deauth_checker.join()

    def start_Detecting_pack2(self):
        os.system("clear")
        self.wireless_interface2 = self.sources.selectadapter()
        os.system("clear")
        if self.sources.checkmode(self.wireless_interface2) == "Monitor" or self.sources.checkmode(self.wireless_interface2) == "Master":
            from changemode import ChangeMode
            self.wireless_interface2 = ChangeMode().changetomanagedmode(self.wireless_interface2)
        os.system("clear")
        input("Please make sure you are connected to target network. Press enter after connected to target network -->")
        ip_address = self.sources.get_ip_address(self.wireless_interface2)
        ip_base = str(ip_address).split(".")
        gateway_ip = f"{ip_base[0]}.{ip_base[1]}.{ip_base[2]}.1"
        print("Configuring Gateway IP and MAC...")
        arp_table = self.sources.capture_mac_address_in_network(self.wireless_interface2)
        try:
            gateway_mac = str(arp_table[gateway_ip]).lower()
        except KeyError:
            print("Could not configure mac address for your network may be due to your network adapter. Change network adapter and Try Again!!!")
            time.sleep(2)
        else:
            os.system("clear")
            while True:
                gateway_ip_check = input(f"Default gateway or router ip and mac address is set to be {gateway_ip}={gateway_mac} if it is correct ip type 'y' or enter. If it is wrong type 'n' to change it -->  ").lower()
                if gateway_ip_check == 'n':
                    new_gateway_ip = input("Input the ip address of your gateway or main router like '192.168.1.1' --> ")
                    if new_gateway_ip in arp_table:
                        gateway_ip = new_gateway_ip
                        try:
                            gateway_mac = str(arp_table[gateway_ip]).lower()
                        except KeyError:
                            print("Could not configure mac address for your network. Try Again!!!")
                        arp_table["gateway_ip"] = gateway_ip
                        break
                    else:
                        ip_confirm = input("This ip address does not captured in arp table. Do you want to select it? y/n --> ").lower()
                        if ip_confirm == "y":
                            gateway_ip = new_gateway_ip
                            try:
                                gateway_mac = str(arp_table[gateway_ip]).lower()
                            except KeyError:
                                gateway_mac = str(self.target_network["bssid"]).lower()
                            arp_table["gateway_ip"] = gateway_ip
                            break
                else:
                    arp_table["gateway_ip"] = gateway_ip
                    break
            
            os.system("clear")
            arp_table_updates = Thread(target=self.sources.arp_table_update_and_spoof_detect, args=(gateway_ip,gateway_mac,self.wireless_interface2,))
            arp_table_updates.start()
            self.sources.check_arp_reponses(self.wireless_interface2)
            self.terminate_thread(arp_table_updates)
            arp_table_updates.join()

    def terminate_thread(self,thread):
        if not thread.is_alive():
            return
        thread_id = thread.ident
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
            ctypes.c_long(thread_id), ctypes.py_object(SystemExit)
        )
        
        if res == 0:
            raise ValueError("Invalid thread id")
        elif res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
            raise SystemError("PyThreadState_SetAsyncExc failed")
        
    def start_full_detecting(self):
        os.system("clear")
        adapters_list = self.sources.listinterfaces()
        while True:
            option1 = input("Select First Network Adaptor for DDOS and Evil Twin Detection by typing corresponding index number (It's mode will be changed to monitor) --> ")
            option2 = input("Select second Network Adaptor for ARP spoofing and MITM attack by typing corresponding index number (It should be connected to Target Network ) --> ")
            try:
                option1 = int(option1)
                option2 = int(option2)
                self.wireless_interface = adapters_list[option1]
                self.wireless_interface2 = adapters_list[option2]
                if option1 == option2:
                    print("[-] Can not select similar network adaptor for both options.. Select Different ones ..")
                    time.sleep(2)
                else:
                    break
            except Exception as e:
                print("[-] Error occurs try again......")
                time.sleep(2)
        os.system("clear")
        if self.sources.checkmode(self.wireless_interface) == "Managed":
            from changemode import ChangeMode
            self.wireless_interface = ChangeMode().changetomonitormode(self.wireless_interface)
        os.system("clear")
        self.target_network = self.sources.select_network(self.wireless_interface)
        os.system("clear")
        input("Make sure your wireless adaptor for arp spoofing and MITM detection should be connected to target network now. If you are connected to target network press 'ENTER' --> ")
        ip_address = self.sources.get_ip_address(self.wireless_interface2)
        ip_base = str(ip_address).split(".")
        print("[+] Configuring Gateway IP and Mac addresses.....")
        try:
            gateway_ip = f"{ip_base[0]}.{ip_base[1]}.{ip_base[2]}.1"
            arp_table = self.sources.capture_mac_address_in_network(self.wireless_interface2)
            gateway_mac = str(arp_table[gateway_ip]).lower()
        except KeyError:
            gateway_mac = str(self.target_network["bssid"]).lower()
        except Exception:
            pass
        else:
            while True:
                gateway_ip_check = input(f"Default gateway or router ip and mac address is set to be {gateway_ip}={gateway_mac} if it is correct ip type 'y' or enter. If it is wrong type 'n' to change it -->  ").lower()
                if gateway_ip_check == 'n':
                    new_gateway_ip = input("Input the ip address of your gateway or main router like '192.168.1.1' --> ")
                    if new_gateway_ip in arp_table:
                        gateway_ip = new_gateway_ip
                        try:
                            gateway_mac = str(arp_table[gateway_ip]).lower()
                        except KeyError:
                            gateway_mac = str(self.target_network["bssid"]).lower()
                        arp_table["gateway_ip"] = gateway_ip
                        break
                    else:
                        ip_confirm = input("This ip address does not captured in arp table. Do you want to select it? y/n --> ").lower()
                        if ip_confirm == "y":
                            gateway_ip = new_gateway_ip
                            try:
                                gateway_mac = str(arp_table[gateway_ip]).lower()
                            except KeyError:
                                gateway_mac = str(self.target_network["bssid"]).lower()
                            arp_table["gateway_ip"] = gateway_ip
                            break

                else:
                    arp_table["gateway_ip"] = gateway_ip
                    break
            
            os.system("clear")
            print("[NOTE]::: If DDOS attack is launched on terget network then network adapter could disconnected by target network as a result the ARP Spoofing and MITM attack detector will be closed and these attacks will not detected. So, Restart this tool again to start everything again....")
            arp_table_updates = Thread(target=self.sources.arp_table_update_and_spoof_detect, args=(gateway_ip,gateway_mac,self.wireless_interface2,))
            arp_table_updates.start()
            arp_checker = Thread(target=self.sources.check_arp_reponses, args=(self.wireless_interface2,))
            arp_checker.start()
        deauth_checker = Thread(target=self.detect_deauth_attack)
        deauth_checker.start()
        self.check_evil_twin_ddos()
        self.terminate_thread(arp_table_updates)
        arp_table_updates.join()
        self.terminate_thread(arp_checker)
        arp_checker.join()
        self.terminate_thread(self.deauth_process)
        self.deauth_process.join()
        self.terminate_thread(deauth_checker)
        deauth_checker.join()
        





        