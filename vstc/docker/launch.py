#!/usr/bin/env python3

import datetime
import logging
import os
import re
import signal
import sys

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


class STC_vm(vrnetlab.VM):
    def __init__(self, hostname, username, password):
        for e in os.listdir("/"):
            if re.search(".qcow2$", e):
                disk_image = "/" + e

        super(STC_vm, self).__init__(
            username, password, disk_image=disk_image, use_scrapli=True, min_dp_nics=1, mgmt_passthrough=True
        )

        self.hostname = hostname
        self.num_nics = 9
        self.nic_type = "virtio-net-pci"
        self.conn_mode = "tc"
        self.wait_pattern = ">>"

    def bootstrap_spin(self):
        """This function should be called periodically to do work."""

        if self.spins > 600:
            # too many spins with no result ->  give up
            self.stop()
            self.start()
            return

        (ridx, match, res) = self.con_expect(
            [b"login:"]
        )
        if match:
            self.bootstrap_config()
            
            self.scrapli_tn.close()
            # startup time?
            startup_time = datetime.datetime.now() - self.start_time
            self.logger.info("Startup complete in: %s", startup_time)
            # mark as running
            self.running = True
            return
        elif res:
            self.write_to_stdout(res)
            
        return
    
    def bootstrap_config(self):        
        # login
        self.wait_write("admin", "")
        self.wait_write("spt_admin", "Password:")
        
        v4_mgmt_address = vrnetlab.cidr_to_ddn(self.mgmt_address_ipv4)
        v6_mgmt_address = self.mgmt_address_ipv6.split("/")
        
        # configure
        self.wait_write("mode static")
        self.wait_write("ipv6mode static")
        
        self.wait_write(f"ipaddress {v4_mgmt_address[0]}")
        self.wait_write(f"netmask {v4_mgmt_address[1]}")
        self.wait_write(f"gwaddress {self.mgmt_gw_ipv4}")
        
        self.wait_write(f"ipv6address {v6_mgmt_address[0]}")
        self.wait_write(f"ipv6prefixlen {v6_mgmt_address[1]}")
        self.wait_write(f"ipv6gwaddress {self.mgmt_gw_ipv6}")
        
        self.wait_write("activate")
        self.wait_write("reboot")
        
        self.con_read_until("login:")

        
class STC(vrnetlab.VR):
    def __init__(self, hostname, username, password):
        super(STC, self).__init__(username, password)
        self.vms = [STC_vm(hostname, username, password)]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="")
    parser.add_argument(
        "--trace", action="store_true", help="enable trace level logging"
    )
    parser.add_argument("--username", default="admin", help="Username")
    parser.add_argument("--password", default="spt_admin", help="Password")
    parser.add_argument("--hostname", default="stc", help="Hostname")
    parser.add_argument("--connection-mode", default="tc", help="Ignored, does nothing")
    
    args = parser.parse_args()

    LOG_FORMAT = "%(asctime)s: %(module)-10s %(levelname)-8s %(message)s"
    logging.basicConfig(format=LOG_FORMAT)
    logger = logging.getLogger()

    logger.setLevel(logging.DEBUG)
    if args.trace:
        logger.setLevel(1)

    vr = STC(
        args.hostname,
        args.username,
        args.password,
    )
    vr.start()
