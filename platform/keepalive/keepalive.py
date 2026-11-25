"""Hold KEEPALIVE_MB of resident memory (platform-keepalive.service).

Oracle reclaims an idle Always Free instance: over 7 days, 95th-percentile CPU, network and (A1
only) memory utilization all under 20 %. A lightly loaded A1 replica sits at ~15 % memory; this
keeps it above, from RAM it does not use anyway. Remove it once the tenancy is Pay As You Go.
"""
import os
import time

ballast = bytearray(int(os.environ.get('KEEPALIVE_MB', '1536')) << 20)
pages = len(ballast[::4096])
while True:
    # Rewrite one byte per page so the pages stay resident and hot (not swapped out as idle).
    ballast[::4096] = bytes([int(time.time()) & 255]) * pages
    time.sleep(600)
