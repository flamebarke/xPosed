#!/usr/bin/python3

#Author: Shain Lakin

import re
import logging
import argparse
from os import system
from itertools import cycle
from shutil import get_terminal_size
from threading import Thread
from time import sleep
from getpass import getpass
from subprocess import PIPE, Popen
from collections import Counter

logging.basicConfig(level=logging.INFO, filename="xposed.log", filemode="a", format='%(message)s')
password = getpass("sudo password: ")
system('clear')

banner= """
██╗  ██╗██████╗  ██████╗ ███████╗███████╗██████╗ 
╚██╗██╔╝██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗
 ╚███╔╝ ██████╔╝██║   ██║███████╗█████╗  ██║  ██║
 ██╔██╗ ██╔═══╝ ██║   ██║╚════██║██╔══╝  ██║  ██║
██╔╝ ██╗██║     ╚██████╔╝███████║███████╗██████╔╝
╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═════╝ 
                                                                                                                                                                                                                                                   
"""
print(banner)

parser = argparse.ArgumentParser(description="xPosed parses text logs for IP addresses and \
    adds a deny rule to UFW if the IP is seen more than the user defined number of allowed times. \
    Can also run a custom command instead of modifying the firewall.", \
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-m", "--mode", type=str, default="deny", help="Set the mode to create either deny or allow rules. Map mode uses scapy to passively map the network.")
parser.add_argument("-l", "--logfile", type=str, required=True, help="Path to logfile to parse.")
parser.add_argument("-w", "--whitelist", type=str, required=True, nargs="+", help="Whitelist IP addresses from automated actions.")
parser.add_argument("-a", "--allow", type=str, nargs="+", help="Allow IP addresses.")
parser.add_argument("-b", "--blacklist", type=str, nargs="+", help="Blacklisted IP addresses.")
parser.add_argument("-p", "--ports", type=str, help="Allowed ports.")
parser.add_argument("-x", "--count", default=10, type=int, help="Number of times ip can be seen before either being banned/allowed or a custom action is taken.")
parser.add_argument("-c", "--custom", type=str, help="Run a custom command instead of ufw.")
args = parser.parse_args()


allowp = "sudo -S ufw allow proto tcp from any to any port "
allow_insert = "sudo -S ufw insert 1 allow proto any from "
deny_insert = "sudo -S ufw insert 1 deny proto any from "
s_allow = "sudo -S ufw allow proto any from "
s_deny = "sudo -S ufw deny proto any from "


class Loader:
    def __init__(self, desc="Loading...", end="Done!...", timeout=0.1):
        """
        A loader-like context manager

        Args:
            desc (str, optional): The loader's description. Defaults to "Loading...".
            end (str, optional): Final print. Defaults to "Done!...".
            timeout (float, optional): Sleep time between prints. Defaults to 0.1.
        """
        self.desc = desc
        self.end = end
        self.timeout = timeout

        self._thread = Thread(target=self._animate, daemon=True)
        self.steps = ["⢿", "⣻", "⣽", "⣾", "⣷", "⣯", "⣟", "⡿"]
        self.done = False

    def start(self):
        self._thread.start()
        return self

    def _animate(self):
        for c in cycle(self.steps):
            if self.done:
                break
            print(f"\r{self.desc} {c}", flush=True, end="")
            sleep(self.timeout)

    def __enter__(self):
        self.start()

    def stop(self):
        self.done = True
        cols = get_terminal_size((80, 20)).columns
        print("\r" + " " * cols, end="", flush=True)
        print(f"\r{self.end}", flush=True)

    def __exit__(self, exc_type, exc_value, tb):
        self.stop()


def proc(cmd):
    try:
        proc = Popen(f"{cmd}".split(), \
            stdin=PIPE, stdout=PIPE, stderr=PIPE)
        proc.communicate(password.encode())
    except KeyboardInterrupt:
        reset()


def reset():
    reset = input("\nReset firewall rules? (y/n): ")
    if reset == "n":
        exit(0)
    else:
        proc("sudo -S ufw --force reset")
        sleep(2)
        exit(0)


def process_log(log):
    pattern = re.compile(r'''((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)''')
    try:
        with open(log,'r') as l:
            ip = []
            valid = []
            for line in l:
                ip += re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)
            for i in ip:
                result = pattern.search(i)
                if result:
                    valid.append(i)
                #print(valid)
            return valid
    except KeyboardInterrupt:
        reset()


def custom(ip):
    try:
        cmd = args.custom.replace("%", f"{ip}")
        loader = Loader(f"Executing : {cmd}...", f"Executed : {cmd}").start()
        proc(args.custom.replace("%", f"{ip}"))
        args.whitelist.append(ip)
        logging.info(cmd)
        loader.stop()
    except KeyboardInterrupt:
        reset()


def map():
    pass


def setup():
    proc("sudo -S ufw enable")
    if args.ports:
        loader = Loader(f"Creating allow rule for : {args.ports}", f"Allowed : {args.ports}").start()
        proc(allowp + args.ports)
        sleep(1)
        loader.stop()
    if args.allow:
        for ip in args.allow:
            allow(ip)
    if args.blacklist:
        for ip in args.blacklist:
            deny(ip)


def deny(ip):
    try:
        loader = Loader(f"Blocking : {ip}", f"Denied : {ip}").start()
        if args.ports:
            proc(deny_insert + ip)
            sleep(1)
        else:
            proc(s_deny + ip)
            sleep(1)
        args.whitelist.append(ip)
        logging.info(ip)
        loader.stop()
    except KeyboardInterrupt:
        reset()


def allow(ip):
    try:
        loader = Loader(f"Allowing : {ip}", f"Allowed : {ip}").start()
        if args.ports:
            proc(allow_insert + ip)
            sleep(1)
        else:
            proc(s_allow + ip)
            sleep(1)
        args.whitelist.append(ip)
        logging.info(ip)
        loader.stop()
    except KeyboardInterrupt:
        reset()


def main():
    setup()
    while True:
        data = process_log(args.logfile)
        sleep(1)
        count = Counter(data)
        for x in (count.keys()):
            if count[x] > args.count:
                try:
                    sleep(1)
                    if x not in args.whitelist:
                        if args.custom:
                            custom(x)
                        if args.mode == "deny":
                            deny(x)
                        if args.mode == "allow":
                            allow(x)
                        if args.mode == "map":
                            map(x)
                except KeyboardInterrupt:
                    reset()


main()
