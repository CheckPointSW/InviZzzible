Contributed By Check Point Software Technologies LTD.<br />
Programmed by Stanislav Skuratovich.<br />
Presented at Virus Bulletin 2016 by Alexander Chailytko and Stanislav Skuratovich.

Overview
========

Sandbox detection tool is a tool for assessment of your virtual environments in an easy an reliable way. It contains the most recent and up to date detection and evasion techniques as well as fixes for them. Also, you can add and expand existing techniques yourself even without modifying the source code.

Slides from Virus Bulletin 2016 Conference: https://github.com/CheckPointSW/VB2016-sandbox-evasion/blob/master/conferences/Skuratovich_Chailytko-vb-2016-defating-sandbox-evasion.pdf

## Supported environments
* Cuckoo Sandbox
* VMWare virtualization products
* VirtualBox

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
* VMDE project
* Pafish project
