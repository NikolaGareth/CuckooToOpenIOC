# GraduationProject
毕业设计：基于OpenIOC的网络威胁情报收集及管理

系统设计思路:

（1）采用cuckoo（杜鹃沙箱，一个通过将恶意程序放入虚拟机中自动分析来自动出报告的系统，最主流的开源恶意程序分析系统）进行威胁情报采集；

（2）使用python进行编程，调用cuckoo的API，将cuckoo中的威胁情报转换成OpenIOC格式；

（3）使用openioc官方的mandiant IOCe进行威胁情报查看和管理；

（4）使用威胁情报中心MISP进行威胁情报的整合。
