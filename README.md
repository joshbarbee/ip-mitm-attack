# MITM IP attack

## Virtual Machine Setup

Right now, I think only two virtual machines are needed.

In VirtualBox, create two machines according to your own specs (RAM, CPU, whatever). After creation, we will enable NAT networks.

* For Virtualbox 7.0.X and later

1. Go to File > Tools > Network Manager
2. Change the tab to the NAT networks tab
3. Create a new NAT network via create button
4. Go to victim VM Settings > Network
5. Change adapter 1 to NAT network, probably named NatNetwork after the network you just created
6. Change MAC address to unique MAC address in advanced tab.
7. Boot machines. If machines were created via clone in VirtualBox, you will need to delete the file `/etc/machine-id` within each VM and then reboot.
8. At this point, VMs should be able to network with each other as well as external internet.

## Set up shared folders to share attacker script

1. Make sure Guest Additions is installed in VirtualBox to enabled Shared Folders. Otherwise, it will be a pain to copy files between. See https://old.reddit.com/r/virtualbox/comments/12vkjwk/where_to_download_guest_additions_iso/ and https://askubuntu.com/questions/22743/how-do-i-install-guest-additions-in-a-virtualbox-vm for any / any issues


2. For the attacker VM, go to Settings > Shared Folders

3. Create a new shared folder with this directory and the VM. Mount anywhere (probably somewhere like ./ip-spoofing)

4. In the attacker machine, CD to that directory and run desired scripts (like start.sh)