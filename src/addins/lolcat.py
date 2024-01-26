#!/usr/bin/env python
#
# "THE BEER-WARE LICENSE" (Revision 43~maze)
#
# <maze@pyth0n.org> wrote these files. As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.
# 
# script below is my modified version of https://github.com/tehmaze/lolcat/blob/master/lolcat

from __future__ import print_function

import atexit
import math
import random
import re
import sys
from signal import signal, SIGPIPE, SIG_DFL

# override default handler so no exceptions on SIGPIPE
signal(SIGPIPE, SIG_DFL)

# Reset terminal colors at exit
def reset():
    sys.stdout.write('\x1b[0m')
    sys.stdout.flush()

atexit.register(reset)


STRIP_ANSI = re.compile(r'\x1b\[(\d+)(;\d+)?(;\d+)?[m|K]')
COLOR_ANSI = (
    (0x00, 0x00, 0x00), (0xcd, 0x00, 0x00),
    (0x00, 0xcd, 0x00), (0xcd, 0xcd, 0x00),
    (0x00, 0x00, 0xee), (0xcd, 0x00, 0xcd),
    (0x00, 0xcd, 0xcd), (0xe5, 0xe5, 0xe5),
    (0x7f, 0x7f, 0x7f), (0xff, 0x00, 0x00),
    (0x00, 0xff, 0x00), (0xff, 0xff, 0x00),
    (0x5c, 0x5c, 0xff), (0xff, 0x00, 0xff),
    (0x00, 0xff, 0xff), (0xff, 0xff, 0xff),
)

class LolCat(object):
    def __init__(self, mode=256, output=sys.stdout):
        self.mode =mode
        self.output = output

    def _distance(self, rgb1, rgb2):
        return sum(map(lambda c: (c[0] - c[1]) ** 2,
            zip(rgb1, rgb2)))

    def ansi(self, rgb):
        r, g, b = rgb

        if self.mode in (8, 16):
            colors = COLOR_ANSI[:self.mode]
            matches = [(self._distance(c, map(int, rgb)), i) for i, c in enumerate(colors)]
            matches.sort()
            color = matches[0][1]

            return '3%d' % (color,)
        else:
            gray_possible = True
            sep = 2.5

            while gray_possible:
                if r < sep or g < sep or b < sep:
                    gray = r < sep and g < sep and b < sep
                    gray_possible = False

                sep += 42.5

            if gray:
                color = 232 + int(float(sum(rgb) / 33.0))
            else:
                color = sum([16]+[int(6 * float(val)/256) * mod
                    for val, mod in zip(rgb, [36, 6, 1])])

            return '38;5;%d' % (color,)

    def wrap(self, *codes):
        return '\x1b[%sm' % (''.join(codes),)

    def rainbow(self, freq, i):
        r = math.sin(freq * i) * 127 + 128
        g = math.sin(freq * i + 2 * math.pi / 3) * 127 + 128
        b = math.sin(freq * i + 4 * math.pi / 3) * 127 + 128
        return [r, g, b]

    def cat(self, fd):
        lines = iter(fd.splitlines())
        os = random.randint(0, 256)
        for line in lines:
            os +=1
            self.println(line, os)

    def println(self, s, os):
        s = s.rstrip()

        self.println_plain(s, os)

        self.output.write('\n')
        self.output.flush()

    def println_plain(self, s, os):
        for i, c in enumerate(s):
            rgb = self.rainbow(0.1, os + i / 3.0) # 0.1 - freq, os (rand int), 3.0 - spread
            self.output.write(''.join([
                self.wrap(self.ansi(rgb)),
                c,
            ]))

def logo(): 
    lolcat = LolCat()
    logo_org = """

  █████████   ██████████         █████          ████  ████            
  ███░░░░░███ ░░███░░░░███       ░░███          ░░███ ░░███            
 ░███    ░███  ░███   ░░███       ░███   ██████  ░███  ░███  █████ ████
 ░███████████  ░███    ░███       ░███  ███░░███ ░███  ░███ ░░███ ░███ 
 ░███░░░░░███  ░███    ░███       ░███ ░███████  ░███  ░███  ░███ ░███ 
 ░███    ░███  ░███    ███  ███   ░███ ░███░░░   ░███  ░███  ░███ ░███ 
 █████   █████ ██████████  ░░████████  ░░██████  █████ █████ ░░███████ 
░░░░░   ░░░░░ ░░░░░░░░░░    ░░░░░░░░    ░░░░░░  ░░░░░ ░░░░░   ░░░░░███ 
                                                              ███ ░███ 
                                              by @hijacky    ░░██████  
                                                              ░░░░░░   
    """
    lolcat.cat(logo_org)
    reset()