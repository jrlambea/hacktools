"""
ufencode.py - Url Full Encode

Converts a text string in a serie of "%" with the hex value of each char/symbol.
Very useful to mask a XSS attack.

Example:
Original: <script>alert(1);</script>
Encoded:  %3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3b%3c%2f%73%63%72%69%70%74%3e
"""
import sys

t=sys.argv[1]
e=""
for c in t:
	e += "%"+hex(ord(c)).replace("0x","")

print e
