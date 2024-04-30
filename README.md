# MITM IP attack

The generated certificates in the certificate folder aren't actual certs. So you aren't compromising anything Github bots!

Uses arpspoof to create a MITM proxy between target and gateway. Then, launches a malicious DNS server which forges certain DNS responses. See example usage for more details on how to run

1. Install all necessary packages (net-tools to see IPs, python, etc) by running `sh setup.sh` with root privileges.
2. Get Victim IP by running `ifconfig` on victim machine.
3. Run `python mitm.py --help` to see how to use the tool.

## Example Usage
The program supports DNS IP spoofing over all DNS requests, as well as only spoofing requests to specific domains. 

Example usage may be:

`python mitm.py -t 10.0.2.15 -g 10.0.2.1 -i enp0s3 -s 1.2.3.4`

This creates a MITM attack between the target IP address `-t` and gateway address `-g`. It will run on the interface `enp0s3` and spoof all DNS requests with the IP address `1.2.3.4`.

To test the MITM attack worked, after running a command similar to the above, run a simple curl/wget command to a HTTP endpoint that does not use HTTPS, For example
1. `example.com`
2. `info.cern.ch`
3. Any arbitrary IP with the above setting of `-s/--spoof-ip`. With the particular setting, all traffic is redirected to `1.2.3.4`
When running curl/wget, you can then see the victim is redirected to the IP `1.2.3.4`, rather than the IP address of the actual web server. From this, you can run a malicious web server at the configured IP address.

* If the interface options `-i/--interface` is not provided, the user will be prompted for an interface to use. This is typically something along the lines of `enp0s3` or `eth0`, not `lo` (the loopback adapter)
* If the option `-s/spoof-ip` is not set, the user will be prompted to create a mapping between hostnames and IP addresses to spoof. This prompt includes the ability to spoof all DNS, similar to the launch argument

### Other `-s/--spoof-ip` options:
`python mitm.py -t 10.0.2.15 -g 10.0.2.1 -i enp0s3 -s 1.2.3.4` will spoof all DNS traffic and replace the IP address with `1.2.3.4`. This can be bad, as if we are running a malicious server, it is difficult to masquerade as any HTTP server. However, it is a lot easier to masquerade as a particular one. As such, there is support for spoofing specific domains

* `python mitm.py -t 10.0.2.15 -g 10.0.2.1 -i enp0s3 -s dns_spoof.json` will spoof according to the key-value pairs in `dns_spoof.json`. Each key should be a hostname and value is the IP address to replace with. JSON file can be replaced with any other JSON file that has a similar format.

* `python mitm.py -t 10.0.2.15 -g 10.0.2.1 -i enp0s3 -s example.com 1.2.3.4 google.com 5.6.7.8` will spoof all DNS to `example.com` to the IP `1.2.3.4` and all DNS requests to `google.com` to `5.6.7.8`. This can be any number of arguments, as long as the host names and IP address are space-separated and each host name has an IP address

DNS requires host names to be suffixed with a `.`. However, this is slightly unintuitive. As such, formatting hostnames such as `google.com.` is not necessary, and any hostnames not suffixed will be automatically suffixed.
