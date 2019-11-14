# InviZzzible

Contributed By Check Point Software Technologies LTD.<br />
Programmed by Stanislav Skuratovich.<br />
Presented at:
- ShmooCon 2017 by Alexander Chailytko and Stanislav Skuratovich.
- Virus Bulletin 2016 by Alexander Chailytko and Stanislav Skuratovich.

Slides: https://github.com/CheckPointSW/InviZzzible/blob/master/conferences/Skuratovich_Chailytko-DefeatingSandboxEvasion.pdf
<br />
Video: https://archive.org/details/ShmooCon2017/ShmooCon2017+-+Defeating+Sandbox+Evasion.mp4

<p align="center">
  <img src="https://github.com/CheckPointSW/InviZzzible/blob/master/logo.png" width="150"/>
</p>

Overview
========

InviZzzible is a tool for assessment of your virtual environments in an easy and reliable way. It contains the most recent and up to date detection and evasion techniques as well as fixes for them. Also, you can add and expand existing techniques yourself even without modifying the source code.

## Supported environments
* Cuckoo Sandbox
* Joe Sandbox
* VMWare virtualization products
* VirtualBox
* Hyper-V
* Parallels
* QEMU
* BOCHS
* Xen
* VirtualPC
* Sandboxie
* Wine

Features
========

* Generic tool that covers a lot of different virtual environment detection techniques and proposes fixes for that.
* Easily extendable; support for new virtual environments can be added quickly.
* As Cuckoo Sandbox is the most prevalent tool used for automated malware analysis, we include the detections of it as well.
*	Ability to introduce new detection techniques not through modifying the source code, but using the JSON configuration files, so the whole community can contribute towards the development of that tool.
* User-friendly reports about the checked environment that can be shared within the organization among the purely technical guys as well as higher management.

Credits
=======

* Aliaksandr Trafimchuk
* Alexey Bukhteyev
* Raman Ladutska
* Yaraslau Harakhavik
* VMDE project
* Pafish project
