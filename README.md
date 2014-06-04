RandomHostMutationBasedonOpenFlow
=================================

Static configurations, especially IP addresses, give the adversaries great opportunities to discover network targets and then launch attacks. Frequently changing hosts’ IP addresses to hide their real ones is a novel method to solve this problem. A recent paper OpenFlow Random Host Mutation: Transparent Moving Target Defense using Software Defined Networking specified this new proactive moving target defense. In this assignment, I implement a simple model to replicate the result of this paper based on Mininet network emulation environment, OpenFlow architecture and protocol, and SDN technique.

The code is based on Pox 0.1.0. The steps to run are as follows.

1. In a terminal on Mininet VM, copy my scripts to pox/ext:
cp ip_mutation.py ~/pox/ext
cp create_topo.py ~/pox/ext

2. In /etc/resolv.conf, add the following:
nameserver 10.0.0.10

3. Run my controller:
cd ~/pox
./pox.py log.level --DEBUG ip_mutation

4. In a second terminal on Mininet VM, start wireshark, clear mininet and run my script to create the topo:
sudo wireshark &
sudo mn -c
cd ~/pox/ext
sudo python create_topo.py

5. In the second terminal, start external hosts' xterm terminals:
mininet> xterm h1 h2

6. In h1 and h2's xterm terminal, ping internal host with its name:
#ping h3

The results of the ping operations will be showed in each external host's xterm terminal.

And the log of the controller will be showed in the first terminal which runs the controller.
