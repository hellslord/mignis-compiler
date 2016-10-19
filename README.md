# Mignis-Compiler
=================

<pre>
Author: Alessio Zennaro
Supervisor: Prof. Riccardo Focardi
A.Y.: 2015/16
Version: 2.5

This is the new Mignis(+) compiler.
It has been created to perform a translation of a Mignis(+) configuration file
into a generic target firewall language (e.g. Netfilter/iptables, Juniper).

At the moment it supports only the translation into the Netfilter/iptables 
language, but the set of languages can be expanded rather easily.


In order to make this work:
1- Unzip the content of the archive and go to the "utils" directory
2- Issue the "make" command
3- Check if mignis.py and tcbin/target_compiler.py have both +x permissions
3- From the directory where mignis.py is located issue the command:
     ./mignis.py IPTABLES path/to/mignis_configuration_file
   Please notice that this produces Netfilter rules.

Issue the command:
     ./mignis.py list
for the complete list of supported target language

In /path/to/mignis_configuration_file will be created two folders:
1- compiled: inside this folder you can find all the files .config written in
   intermediate representation
2- final: inside this folder you can find all the files .iptables written in
   iptables language.


Version 2.5 new features:
* The language used by Juniper devices (running JunOS) is now supported in beta.
  Please notice that this is the first version that support a target language
  other than iptables. Bugs or slightly wrong rules could affect this version.
  PLEASE USE JUNOS SUPPORT WITH CAUTIONS!!

2016-10-19

</pre>
