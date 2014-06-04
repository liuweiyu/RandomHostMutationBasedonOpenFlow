#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet

from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI

from mininet.node import *

import os

class createSwitchTopo(Topo):
      def __init__(self, n=3, **opts):
          Topo.__init__(self, **opts)
          switch = self.addSwitch('s1')
          for h in range(n):
              host=self.addHost('h%s' % (h+1), ip = '10.0.0.%d' % (h+1))
              self.addLink(host, switch)

def startpings(net):
    hosts = net.hosts
    for host in hosts:
        if host.name != 'h3':
           host.cmd('ifconfig lo up')
           cmd = ( ' echo -n %s "->" $ip' % host.IP() +
                   '    ping -c1 -w 1 10.0.0.77; '
                   ' done&' )
           host.cmd( cmd )
           print ('*** Host %s (%s) will be pinging ips: 10.0.0.77' %
                   (host.name, host.IP()))

if __name__ == '__main__':
    setLogLevel( 'info' )
    net = Mininet(topo= createSwitchTopo(3),  controller=RemoteController)
    net.start()
    CLI(net)
    net.stop()
