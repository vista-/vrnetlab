#!/usr/bin/env python3

import datetime
import logging
import os
import re
import signal
import sys
import telnetlib

import vrnetlab

def handle_SIGCHLD(signal, frame):
    os.waitpid(-1, os.WNOHANG)

def handle_SIGTERM(signal, frame):
    sys.exit(0)

signal.signal(signal.SIGINT, handle_SIGTERM)
signal.signal(signal.SIGTERM, handle_SIGTERM)
signal.signal(signal.SIGCHLD, handle_SIGCHLD)

TRACE_LEVEL_NUM = 9
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")
def trace(self, message, *args, **kws):
    # Yes, logger takes its '*args' as 'args'.
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kws)
logging.Logger.trace = trace

class OpenWRT_vm(vrnetlab.VM):
    def __init__(self, username, password, conn_mode, hostname, lan_ip, lan_netmask):
        for e in os.listdir("/"):
            if re.search(".img$", e):
                disk_image = "/" + e
        super(OpenWRT_vm, self).__init__(username, password, disk_image=disk_image, ram=128)
        self.conn_mode=conn_mode
        self.hostname=hostname
        self.lan_ip=lan_ip
        self.lan_netmask=lan_netmask

        self.nic_type = "virtio-net-pci"
        self.num_nics = 1
        self.interface_alias_regexp = r"wan"
        # Data interface numbering offset does not apply

    def calculate_interface_offset(self, intf):
        """ Always return 1, since only a single wan interface is provisioned. """
        return 1

    def bootstrap_spin(self):
        """ This function should be called periodically to do work.
        """

        if self.spins > 300:
            # too many spins with no result ->  give up
            self.stop()
            self.start()
            return

        (ridx, match, res) = self.tn.expect([b"br-lan"], 1)
        if match: # got a match!
            if ridx == 0: # login
                self.logger.debug("VM started")
                # run main config!
                self.bootstrap_config()
                # close telnet connection
                self.tn.close()
                # startup time?
                startup_time = datetime.datetime.now() - self.start_time
                self.logger.info("Startup complete in: %s" % startup_time)
                # mark as running
                self.running = True
                return

        # no match, if we saw some output from the router it's probably
        # booting, so let's give it some more time
        if res != b'':
            self.logger.trace("OUTPUT: %s" % res.decode())
            # reset spins if we saw some output
            self.spins = 0

        self.spins += 1

        return

    def bootstrap_config(self):
        """ Do the actual bootstrap config
        """
        self.logger.info("applying bootstrap configuration")
        # Get a prompt
        self.wait_write("\r", None)
        # Configure interface
        self.wait_write("ifconfig br-lan " + self.lan_ip + " netmask " + self.lan_netmask, "#")
        # Set root password (ssh login prerequisite)
        self.wait_write("passwd", "#")
        self.wait_write(self.password, "New password:")
        self.wait_write(self.password, "Retype password:")
        # Create vrnetlab user
        self.wait_write("echo '%s:x:501:501:%s:/home/%s:/bin/ash' >> /etc/passwd" %(self.username, self.username, self.username), "#")
        self.wait_write("passwd %s" %(self.username))
        self.wait_write(self.password, "New password:")
        self.wait_write(self.password, "Retype password:")
        # Add user to root group
        self.wait_write("sed -i '1d' /etc/group", "#")
        self.wait_write("sed -i '1i root:x:0:%s' /etc/group" % (self.username))
        # Create home dir
        self.wait_write("mkdir -p /home/%s" %(self.username))
        self.wait_write("chown %s /home/%s" %(self.username, self.username))
        self.wait_write("chown %s /etc/config/ -R" %(self.username))
        self.logger.info("completed bootstrap configuration")

class OpenWRT(vrnetlab.VR):
    def __init__(self, username, password, conn_mode, hostname, lan_ip, lan_netmask):
        super(OpenWRT, self).__init__(username, password)
        self.vms = [ OpenWRT_vm(username, password, conn_mode, hostname, lan_ip, lan_netmask) ]

import click
@click.command()
@click.option('--tracing', is_flag=True, help='enable trace level logging')
@click.option('--username','-u', default='root',   envvar='USERNAME', required=True, help="Username")
@click.option('--password','-p', default='VR-netlab9', envvar='PASSWORD', required=True, help="Password")
@click.option('--connection-mode','-c', default='tc', envvar='CONNECTION_MODE', required=True, help="connection mode")
@click.option('--hostname','-h', default='OpenWRT', envvar='HOSTNAME', required=True, help="Hostname")
@click.option('--lan-ip','-ip', default='10.0.0.15', envvar='LAN_IP', required=True, help="Lan IP")
@click.option('--lan-netmask','-mask', default='255.255.255.0', envvar='LAN_NETMASK', required=True, help="Lan netmask")

def args(tracing,username,password,connection_mode,hostname,lan_ip,lan_netmask):
        LOG_FORMAT = "%(asctime)s: %(module)-10s %(levelname)-8s %(message)s"
        logging.basicConfig(format=LOG_FORMAT)
        logger = logging.getLogger()

        logger.setLevel(logging.DEBUG)
        if tracing:
            logger.setLevel(1)

        vr = OpenWRT(username, password, connection_mode, hostname, lan_ip, lan_netmask)
        vr.start()

if __name__ == '__main__':
    args()
    # import argparse
    # parser = argparse.ArgumentParser(description='')
    # parser.add_argument('--trace', action='store_true', help='enable trace level logging')
    # parser.add_argument('--username', default='vrnetlab', help='Username')
    # parser.add_argument('--password', default='VR-netlab9', help='Password')
    # parser.add_argument(
    #     "--connection-mode",
    #     default="vrxcon",
    #     help="Connection mode to use in the datapath",
    # )
    # args = parser.parse_args()
