<h1 align="center"> Qscan </h1>

<p align="center">
<img src="https://img.shields.io/badge/go-1.23-blue" />

<p align="center"> 一个速度极快的内网扫描器，具备端口扫描、协议检测、指纹识别，暴力破解，漏洞探测等功能。支持协议1200+，协议指纹10000+，应用指纹20000+，暴力破解协议10余种 </p>

<p align="center"> 中文文档 | <a href="README.en.md">English</a> </p>

# 🚀 上手指南

📢 请务必花一点时间阅读此文档，有助于你快速熟悉JYso！

🧐 使用文档[Wiki](https://github.com/qi4L/qscan/wiki)。

✔ 下载最新版本的[Releases](https://github.com/qi4L/qscan/releases)。

# 👍 特点

+ spy 模式极速遍历常见B段，比常见的一个一个遍历，快上很多倍；
+ 在精确识别端口的同时，又拥有极快的速度；
  + 线程池优化：减少内存分配和 GC 开销；
  + 模板缓存：减少重复构建；
  + 并行发送：榨干多核 CPU；
  + 批量处理：减少系统调用；
  + 并行处理管道： 接收、解析、处理三阶段并行，效率最大化；
  + 缓冲区优化: 增加 Channel 缓冲区，避免阻塞；

# ✨ 404星链计划
<img src lazysrc="https://github.com/knownsec/404StarLink-Project/raw/master/logo.png" width="30%">
Qscan 现已加入 [404星链计划](https://github.com/knownsec/404StarLink)

# 和Fscan对比的优势

+ 同端口数，同线程数下的速度对比：

QScan
![img.png](assets/qscan速度.png)

FScan
![img.png](assets/FScan.png)

# 参考

https://github.com/lcvvvv/kscan

https://github.com/shadow1ng/fscan