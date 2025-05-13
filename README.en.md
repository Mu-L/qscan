<h1 align="center"> Qscan </h1>

<p align="center">
<img src="https://img.shields.io/badge/go-1.23-blue"  alt=""/>

<p align="center"> An ultra-fast intranet scanner featuring port scanning, protocol detection, fingerprint identification, brute force cracking, and vulnerability detection. Supports 1200+ protocols, 10,000+ protocol fingerprints, 20,000+ application fingerprints, and over 10 brute force protocols. </p>

<p align="center"> <a href="README.md">Chinese Documentation</a> | English </p>

# 🚀 Quick Start Guide

📢 Please take a moment to read this documentation—it will help you quickly get familiar with JYso!

🧐 Usage documentation available on [Wiki](https://github.com/qi4L/qscan/wiki).

✔ Download the latest version from [Releases](https://github.com/qi4L/qscan/releases).

# 👍 Key Features

+ Spy mode enables ultra-fast scanning of common B-segments, significantly faster than conventional sequential scanning;
+ Combines precise port identification with blazing-fast speed:
    + Thread pool optimization: Reduces memory allocation and GC overhead;
    + Template caching: Minimizes redundant construction;
    + Parallel transmission: Maximizes multi-core CPU utilization;
    + Batch processing: Reduces system calls;
    + Parallel processing pipeline: Parallel receiving, parsing, and processing for maximum efficiency;
    + Buffer optimization: Increased channel buffer size to prevent blocking;

# ✨ 404Starlink
<img src lazysrc="https://github.com/knownsec/404StarLink-Project/raw/master/logo.png" width="30%">
Qscan has joined [404Starlink](https://github.com/knownsec/404StarLink)

# Advantages Over Fscan

+ Speed comparison with the same number of ports and threads:

QScan
![img.png](assets/qscan速度.png)

FScan
![img.png](assets/FScan.png)

# References

https://github.com/lcvvvv/kscan

https://github.com/shadow1ng/fscan