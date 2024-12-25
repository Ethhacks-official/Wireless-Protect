
# EthHacks Wireless Protect

EthHacks Wireless Protect application is an open source application to detect most common wifi or wireless attacks with in the network. This is terminal version of Wireless Protect application.

- Programming Language: Python3
- Operating System Type: Linux
- Tested On: Kali linux 2024


## Requirements

The Wireless-Protect folder contains "requirements.txt" file. Its contains all the required python libraries for this tool. Install them manualy by using:

```bash
  sudo pip3 install [library]
```
    
OR use the requirements.txt file and install as:

```bash
  sudo pip3 install -r requirements.txt
```
## Options

1.  Deauth Detector, Evil Twin Detector , Clonned Wifi Detector -->  You can select this option by pressing '0' after running the application. In this option, application detect deauthentication attack, Evil Twin attack or Clonned wifi attack on selected network. After selecting this option, You need to select the network adapter for detect these attack and the mode of this network adapter will be changed to monitor mode if its mode is not monitor mode. Then, application will check for nearby wifi networks and show them to select your target network. Application then detect the above mentioned attacks on selected network and notify when any attack detected.

- Deauthentication Attack Detection
- Evil Twin Attack Detection
- Clonned Wifi Detection
---

2.  Arp Spoofing and MITM Detector -->  You can select this option by pressing '1' after running the application. In this option, application detect arp Spoofing attack and man in the middle attack in selected network on your device. After selecting this option, You need to select the network adapter for detect these attack and the mode of this network adapter should me managed mode. Also, you be connected to your target network in which you want to detect above mentioned attacks. Application will check for gateway ip and mac address of network you are connected to. Application then detect the above mentioned attacks in selected network on your device and notify when any attack detected.

- Arp Spoofing Attack Detection
- (MITM) Man in the Middle Attack Detection
---

3.  Detect All including both 1 and 2.. -->  You can select this option by pressing '2' after running the application. In this option, application detect deauthentication attack, Evil Twin attack, Clonned Wifi attack, arp Spoofing attack and man in the middle attack in selected network. After selecting this option, You need to select the 2 network adapter for detecting these attack and the mode of one network adapter will be converted to monitor mode to detect deauthentication, evil twin and clonned wifi attacks. The second network adapter should be in managed mode and should be connected to target or selected network.Then, application will check for nearby wifi networks and show them to select your target network. Application will check for gateway ip and mac address of network you are connected to using second network adapter.  Application then detect the above mentioned attacks in selected network and notify when any attack detected.


[Note] You cannot select same network adapter for both in this option. As, one network adapter will be in monitor mode and other will be in managed mode for proper working.

- Deauthentication Attack Detection
- Evil Twin Attack Detection
- Clonned Wifi Detection
- Arp Spoofing Attack Detection
- (MITM) Man in the Middle Attack Detection
---
## Usage/Installation

After installing the requirements using "requirements.txt". Run the program using following command:

```
sudo python3 main.py
```


## Features

When any of the attack is detected. The application will have below features to allert you.

- `Allert Message on Terminal`

- `Send System Notification`

