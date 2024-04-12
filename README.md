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

You may encounter weird graphical issues when using Ubuntu 22.04 with Guest Additions. This is due to Virtualbox not being compatible
with the latest release of Ubuntu drivers. The fix is to disable Wayland and use Xorg instead. Follow this to turn Wayland off: `https://linuxconfig.org/how-to-enable-disable-wayland-on-ubuntu-22-04-desktop`

## Set up shared folders to share attacker script

1. Make sure Guest Additions is installed in VirtualBox to enabled Shared Folders. Otherwise, it will be a pain to copy files between. See https://old.reddit.com/r/virtualbox/comments/12vkjwk/where_to_download_guest_additions_iso/ and https://askubuntu.com/questions/22743/how-do-i-install-guest-additions-in-a-virtualbox-vm for any / any issues

2. For the attacker VM, go to Settings > Shared Folders

3. Create a new shared folder with this directory and the VM. Mount anywhere (probably somewhere like ./ip-spoofing)

4. In the attacker machine, CD to that directory and run desired scripts (like start.sh)

## Running attacks

1. Install all necessary packages (net-tools to see IPs, python, etc) by running `sh setup.sh` with root privileges.
2. Get Victim IP by running `ifconfig` on victim machine.
3. Run `python mitm.py --help` to see how to use the tool.

## Example Usage
The program supports DNS IP spoofing over all DNS requests, as well as only spoofing requests to specific domains. 

Example usage may be:

`python mitm.py -t 10.0.2.15 -g 10.0.2.1 -i enp0s3 -s 1.2.3.4`

This creates a MITM attack between the target IP address `-t` and gateway address `-g`. It will run on the interface `enp0s3` and spoof all DNS requests with the IP address `1.2.3.4`.

* If the interface options `-i/--interface` is not provided, the user will be prompted for an interface to use. This is typically something along the lines of `enp0s3` or `eth0`, not `lo` (the loopback adapter)
* If the option `-s/spoof-ip` is not set, the user will be prompted to create a mapping between hostnames and IP addresses to spoof. This prompt includes the ability to spoof all DNS, similar to the launch argument

### Other `-s/--spoof-ip` options:
`python mitm.py -t 10.0.2.15 -g 10.0.2.1 -i enp0s3 -s 1.2.3.4` will spoof all DNS traffic and replace the IP address with `1.2.3.4`. This can be bad, as if we are running a malicious server, it is difficult to masquerade as any HTTP server. However, it is a lot easier to masquerade as a particular one. As such, there is support for spoofing specific domains

* `python mitm.py -t 10.0.2.15 -g 10.0.2.1 -i enp0s3 -s dns_spoof.json` will spoof according to the key-value pairs in `dns_spoof.json`. Each key should be a hostname and value is the IP address to replace with. JSON file can be replaced with any other JSON file that has a similar format.

* `python mitm.py -t 10.0.2.15 -g 10.0.2.1 -i enp0s3 -s example.com 1.2.3.4 google.com 5.6.7.8` will spoof all DNS to `example.com` to the IP `1.2.3.4` and all DNS requests to `google.com` to `5.6.7.8`. This can be any number of arguments, as long as the host names and IP address are space-separated and each host name has an IP address

DNS requires host names to be suffixed with a `.`. However, this is slightly unintuitive. As such, formatting hostnames such as `google.com.` is not necessary, and any hostnames not suffixed will be automatically suffixed.