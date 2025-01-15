import sys
import os

sys.path.insert(1, f'{os.getcwd()}/src')
from setup import Setup # type: ignore
from colorama import init, Fore
init()
GREEN = Fore.GREEN
RED   = Fore.RED
BLUE   = Fore.BLUE
RESET = Fore.RESET



def banner():
    print(f"{RED}         Welcome to EthHacks Wireless Protect Tool         {RESET}")
    print(f"""{RED}
     ______ _   _     _    _            _        
    |  ____| | | |   | |  | |          | |       
    | |__  | |_| |__ | |__| | __ _  ___| | _____ {RESET}{BLUE}
    |  __| | __| '_ \|  __  |/ _` |/ __| |/ / __|
    | |____| |_| | | | |  | | (_| | (__|   <\___ {RESET}{GREEN}
    |______|\__|_| |_|_|  |_|\__,_|\___|_|\_\___|
        {RESET}""")
    print("\n")
    print("----------------------------------------------------------------------------")


def print_help():

    print(f"""

{RED}\t\t\tEthHacks Wireless Protect{RESET}

{GREEN}EthHacks Wireless Protect application is an open source application to detect most common wifi or wireless attacks with in the network. This is terminal version of Wireless Protect application.

- Programming Language: Python3
- Operating System Type: Linux
- Tested On: Kali linux 2024
{RESET}

{RED}\t\t\tRequirements{RESET}

{GREEN}
The Wireless-Protect folder contains "requirements.txt" file. Its contains all the required python libraries for this tool. Install them manualy by using:
{RESET}
{BLUE}

COMMAND-->{RESET}  sudo pip3 install [library]

{GREEN}
OR use the requirements.txt file and install as:
{RESET}

{BLUE}COMMAND-->{RESET}  sudo pip3 install -r requirements.txt

{RED}\t\t\tOptions{RESET}
{BLUE}
1.  Deauth Detector, Evil Twin Detector , Clonned Wifi Detector --> {RESET}{GREEN} You can select this option by pressing '0' after running the application. In this option, application detect deauthentication attack, Evil Twin attack or Clonned wifi attack on selected network. After selecting this option, You need to select the network adapter for detect these attack and the mode of this network adapter will be changed to monitor mode if its mode is not monitor mode. Then, application will check for nearby wifi networks and show them to select your target network. Application then detect the above mentioned attacks on selected network and notify when any attack detected.

- Deauthentication Attack Detection
- Evil Twin Attack Detection
- Clonned Wifi Detection

{RESET}
{BLUE}
2.  Arp Spoofing and MITM Detector --> {RESET}{GREEN} You can select this option by pressing '1' after running the application. In this option, application detect arp Spoofing attack and man in the middle attack in selected network. After selecting this option, You need to select the network adapter for detect these attack and the mode of this network adapter should me managed mode. Also, you be connected to your target network in which you want to detect above mentioned attacks. Application will check for gateway ip and mac address of network you are connected to. Application then detect the above mentioned attacks in selected network and notify when any attack detected.

- Arp Spoofing Attack Detection
- (MITM) Man in the Middle Attack Detection
{RESET}
{BLUE}
3.  Detect All including both 1 and 2.. --> {RESET}{GREEN} You can select this option by pressing '2' after running the application. In this option, application detect deauthentication attack, Evil Twin attack, Clonned Wifi attack, arp Spoofing attack and man in the middle attack in selected network. After selecting this option, You need to select the 2 network adapter for detecting these attack and the mode of one network adapter will be converted to monitor mode to detect deauthentication, evil twin and clonned wifi attacks. The second network adapter should be in managed mode and should be connected to target or selected network.Then, application will check for nearby wifi networks and show them to select your target network. Application will check for gateway ip and mac address of network you are connected to using second network adapter.  Application then detect the above mentioned attacks in selected network and notify when any attack detected.


[Note] You cannot select same network adapter for both in this option. As, one network adapter will be in monitor mode and other will be in managed mode for proper working.

- Deauthentication Attack Detection
- Evil Twin Attack Detection
- Clonned Wifi Detection
- Arp Spoofing Attack Detection
- (MITM) Man in the Middle Attack Detection

{RESET}

{RED}\t\t\tUsage/Installation
{RESET}
{GREEN}
After installing the requirements using "requirements.txt". Run the program using following command:
{RESET}
{BLUE}
COMMAND-->{RESET} sudo python3 main.py



{RED}\t\t\tFeatures
{RESET}
{GREEN}
When any of the attack is detected. The application will have below features to allert you.

- Allert Message on Terminal

- Send System Notification

{RESET}

    """)



ON = True
while ON:
    os.system("clear")
    banner()
    print("0. Deauth Detector, Evil Twin Detector, Clonned Wifi Detector  (Requires 1 network adapter that can be Built-in Adaptor)")
    print("1. Arp Spoofing and MITM detector (Requires 1 network adapter connected to selected network)")
    print("2. Detect All including both 0 and 1.. (Requires 2 network adapter.. One connected to network)")
    print("3. Help....")
    print("4. Exit")
    selected_option = input("Select the option by typing corresponding index number e.g 0 or 4 --> ")
    if selected_option == "4" or selected_option.upper() == "EXIT":
        ON = False
    elif selected_option == "0":
        Setup().start_Detecting_pack1()
    elif selected_option == "1":
        Setup().start_Detecting_pack2()
    elif selected_option == "2":
        Setup().start_full_detecting()
    elif selected_option == "3":
        os.system("clear")
        print_help()
        print("\n\n")
        input("Press enter to quit --> ")




