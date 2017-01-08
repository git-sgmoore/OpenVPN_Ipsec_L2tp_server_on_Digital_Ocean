#Create SSH Keys - CLIENT COMPUTER
#Check for existing SSH keys
ls -al ~/.ssh
#Generate new SSH key
ssh-keygen -t rsa -b 4096 -C (eg.your_email@example.com)
Press enter
Enter passphrase
#The public key is now located in /home/demo/.ssh/id_rsa.pub The private key (identification) is now located in /home/demo/.ssh/id_rsa
#Add your keys to the droplet when creating it

#Login after creating droplet
#Login as root
ssh root@server_ip_address (eg.45.55.35.23)
#Create new user
adduser vpnrsa
#Give root privileges
gpasswd -a vpnrsa sudo
#Add public key authentication for new user
ssh-keygen -t rsa -b 4096 -C your_email@example.com
#Manually install the key. Copy the public key by ctrl-c or (cat ~/.ssh/id_rsa.pub)
su - vpnrsa
mkdir .ssh
chmod 700 .ssh
#Paste in public key while in nano
nano .ssh/authorized_keys
chmod 600 .ssh/authorized_keys
#exit will return to root
exit
#Now you can log in as the new user
(45.55.35.23 is root=1-7, vpnrsa=3-9)

#Install OpenVPN
wget git.io/vpn --no-check-certificate -O openvpn-install.sh && bash openvpn-install.sh
#Copy unified .ovpn to client computer
scp -P root@45.55.35.23:vpnrsa.ovpn Downloads/

#Disable root login
sudo nano /etc/ssh/sshd_config
PermitRootLogin without-password
PasswordAuthentication no
#To change SSH port - ALLOW NEW PORT IN UFW RULES BELOW AND RESTART UFW BEFORE RESTARTING SSH
Port 22713
reload ssh
sudo restart ssh

#Enable UFW
ufw limit 22713
ufw allow 1194/udp
sudo nano /etc/default/ufw
#Change from DROP to ACCEPT
DEFAULT_FORWARD_POLICY="ACCEPT"
sudo nano /etc/ufw/before.rules
# Add these lines in to the before.rules file
-------------
# START OPENVPN RULES
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]
# Allow traffic from OpenVPN client to eth0
-A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE
COMMIT
# END OPENVPN RULES
------------
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), allow (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22713                      LIMIT IN    Anywhere
1194/udp                   ALLOW IN    Anywhere
500/udp                    ALLOW IN    Anywhere
4500/udp                   ALLOW IN    Anywhere
1194/udp (v6)              ALLOW IN    Anywhere (v6)
22713 (v6)                 LIMIT IN    Anywhere (v6)
500/udp (v6)               ALLOW IN    Anywhere (v6)
4500/udp (v6)              ALLOW IN    Anywhere (v6)
------------
#https://www.digitalocean.com/community/tutorials/3-ways-to-securely-browse-the-internet-with-openvpn-on-debian-8
hostname (eg. ubuntu-vpnrsa)

#Install Dnsmasq
#Check your current nameserver configuration with the following command.
cat /etc/resolv.conf
#Install Dnsmasq
sudo apt-get install dnsmasq
cat /etc/resolv.conf
#Take note of query time
dig digitalocean.com @localhost
#Check again after cached
dig digitalocean.com @localhost

#Allow multiple clients to connect with same ovpn file. Better to create multiple ovpn files
sudo nano /etc/openvpn/server.conf
#Uncomment following line:
duplicate-n
#Restart OpenVPN service
sudo service openvpn restart

#Configure NTP sync
sudo apt-get update
sudo apt-get install ntp
#Configure timezone to UTC
sudo dpkg-reconfigure tzdata
sudo ntpdate pool.ntp.org
sudo service ntp start

#Enable Automatic Upgrades
sudo apt-get install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades

#Autostart OpenVPN on Debian - CLIENT COMPUTER
sudo nano /etc/default/openvpn
#Uncomment:
AUTOSTART=all
#Copy client.ovpn to /etc/openvpn/client.conf by renaming file
gksu -w -u root gksu thunar
#Reload openvpn configuration
/etc/init.d/openvpn reload /etc/openvpn/client.conf
#Check for tun0 interface
ifconfig

#Install send only SSMTP service
sudo apt-get install ssmtp
sudo nano /etc/ssmtp/ssmtp.conf
----------
#root=postmaster
root=0sgmoore0@gmail.com
#mailhub=mail
mailhub=smtp.gmail.com:587
AuthUser=0sgmoore0@gmail.com
AuthPass=3483a3483
UseTLS=YES
UseSTARTTLS=YES
#rewriteDomain=
rewriteDomain=gmail.com
#hostname=ubuntu-vpnrsa
hostname=0sgmoore0@gmail.com
-------------
#Test sstp in terminal
ssmtp recipient_email@example.com
#Format message as below:
To: recipient_email@example.com
From: myemailaddress@gmail.com
Subject: test email

hello world!
#Note the blank line after the subject, everything after this line is the body of the email. When you're finished, press Ctrl-D. sSMTP may take a few seconds to send the message before closing.

#Setup fail2ban
sudo apt-get install fail2ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local
---------
# "ignoreip" can be an IP address, a CIDR mask or a DNS host
ignoreip = 127.0.0.⅛ 45.55.35.23 2600:1003:b842:d5bd:59e8:b3d7:7e47:c6b1 70.199.195.147
bantime  = 600
maxretry = 3
#Setup ssmtp settings with following settings
destemail = 0@sgmoore.com
sendername = Fail2Ban
mta = sendmail
#_mwl sends email with logs
action = %(action_mwl)s
---------
#Jails we can initially set to true without any errors
ssh
dropbear
pam-generic
ssh-ddos
postfix
couriersmtp
courierauth
sasl
dovecot
#Restart fail2ban
sudo service fail2ban stop
sudo service fail2ban start
#Check list of banned IP for fail2ban
fail2ban-client status ssh
iptables --list -n | fgrep DROP

#Full system backup using rsync.
#Using the -aAX set of options, all attributes are preserved
rsync -aAXv --exclude={"/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found"} root@45.55.35.23:/ /home/test_2/vpnrsa_backup/

#Configuring TripWire
sudo apt-get install tripwire
#Site-Key passphrase
My2-8
#Local-Key passphrase
My3-9
#Create policy file
sudo twadmin --create-polfile /etc/tripwire/twpol.txt
#Initialize database
sudo tripwire --init
sudo sh -c 'tripwire --check | grep Filename > /etc/tripwire/test_results'
#Entries look like this:
less /etc/tripwire/test_results
-------------
     Filename: /etc/rc.boot
     Filename: /root/mail
     Filename: /root/Mail
     Filename: /root/.xsession-errors
     Filename: /root/.xauth
     Filename: /root/.tcshrc
     Filename: /root/.sawfish
     Filename: /root/.pinerc
     Filename: /root/.mc
     Filename: /root/.gnome_private
     Filename: /root/.gnome-desktop
     Filename: /root/.gnome
     Filename: /root/.esd_auth
     Filename: /root/.elm
     Filename: /root/.cshrc
     Filename: /root/.bash_profile
     Filename: /root/.bash_logout
     Filename: /root/.amandahosts
     Filename: /root/.addressbook.lu
     Filename: /root/.addressbook
     Filename: /root/.Xresources
     Filename: /root/.Xauthority
     Filename: /root/.ICEauthority
     Filename: /proc/30400/fd/3
     Filename: /proc/30400/fdinfo/3
     Filename: /proc/30400/task/30400/fd/3
     Filename: /proc/30400/task/30400/fdinfo/3
----------------
#Edit text policy in editor
sudo nano /etc/tripwire/twpol.txt
#Search for each of the files that were returned in the test_results file. Comment out lines that match.
{
        /dev                    -> $(Device) ;
        /dev/pts                -> $(Device) ;
        #/proc                  -> $(Device) ;
        /proc/devices           -> $(Device) ;
        /proc/net               -> $(Device) ;
        /proc/tty               -> $(Device) ;
        . . .


#Comment out /var/run and /var/lock lines so that system does not flag normal filesystem changes by services:
(
  rulename = "System boot changes",
  severity = $(SIG_HI)
)
{
        #/var/lock              -> $(SEC_CONFIG) ;
        #/var/run               -> $(SEC_CONFIG) ; # daemon PIDs
        /var/log                -> $(SEC_CONFIG) ;
}
#Save and close
#Implement by re-creating encrypted policy file that tripwire reads
sudo twadmin -m P /etc/tripwire/twpol.txt
#Reinitialize the database to implement policy
sudo tripwire --init
#Warnings should be gone. If there are still warnings, continue editing /etc/tripwire/twpol.txt file until gone.
#The basic syntax for a check is
sudo tripwire --check
#Delete the test_results file that we created
sudo rm /etc/tripwire/test_results
#Remove plain text configuration files
sudo sh -c 'twadmin --print-polfile > /etc/tripwire/twpol.txt'
#Move text version to backup location and recreate it
sudo mv /etc/tripwire/twpol.txt /etc/tripwire/twpol.txt.bak
sudo sh -c 'twadmin --print-polfile > /etc/tripwire/twpol.txt'
#Remove plain text files
sudo rm /etc/tripwire/twpol.txt
sudo rm /etc/tripwire/twpol.txt.bak
#Send an email notifications
sudo apt-get install mailutils
#See if we can send email
sudo tripwire --check | mail -s "Tripwire report for `uname -n`" 0@sgmoore.com
#Check report that was sent with the email
sudo tripwire --check --interactive
#Remove “x” from box if not ok with change
#Automate Tripwire with Cron
#Check to see if root already has a crontab by issuing this command:
sudo crontab -l
#If a crontab is present, you should pipe it into a file to back it up:
sudo sh -c 'crontab -l > crontab.bad'
#Afterwards, we can edit the crontab by typing:
sudo crontab -e
#To have tripwire run at 3:30am every day, we can place a line like this in our file:
30 3 * * * /usr/sbin/tripwire --check | mail -s "Tripwire report for `uname -n`" 0@sgmoore.com


#Maintenance Commands
#Programs holding an open network socket
lsof -i
#Show all running processes
ps -ef
#Who is logged on
who -u
#Kill the process that you want
kill "pid"
#Check SSH sessions
ps aux | egrep "sshd: [a-zA-Z]+@"
#Check SSHD
ps fax
#Check last logins
last
#Check ufw status
sudo ufw status verbose
#Delete ufw rules
sudo ufw delete deny "port"
#Check logs
grep -ir ssh /var/log/* 
grep -ir sshd /var/log/* 
grep -ir breakin /var/log/* 
grep -ir security /var/log/*
#Tree directory http://www.cyberciti.biz/faq/linux-show-directory-structure-command-line/
#See all files
tree -a
#List directories only
tree -d
#Colorized output
tree -C
#File management
https://www.digitalocean.com/community/tutorials/basic-linux-navigation-and-file-management
http://www.computerworld.com/article/2598082/linux/linux-linux-command-line-cheat-sheet.html
http://www.debian-tutorials.com/beginners-how-to-navigate-the-linux-filesystem
#LSOF Commands
https://stackoverflow.com/questions/106234/lsof-survival-guide
#How to kill zombie process
ps aux | grep 'Z'
#Find the parent PID of the zombie
pstree -p -s 93572
#Check IPTables traffic
sudo iptables -v -x -n -L
#Report file system disk space
df -Th
#Check trash size
sudo find / -type d -name '*Trash*' | sudo xargs du -h | sort
#Check size of packages in apt
du -h /var/cache/apt/
#Check size of log files
sudo du -h /var/log
#Check size of lost+found folder
sudo find / -name "lost+found" | sudo xargs du -h
#How to delete lots of text in nano
#Scroll to top of text, press Alt+A, Ctrl-V to bottom of text, press Ctrl-K to cut the text, Ctrl-O to save, Ctrl-X to exit
#How to scan top 8000 ports using nmap
nmap -vv --top-ports 8000 45.55.35.23

#Check for malware
#Download list of malware
wget https://gist.githubusercontent.com/hwdsl2/9737420/raw/b2d8d0cd63af8a3c709238614e5e421748b57751/mwlist.txt
#Sort MD5 checksums of list
grep ^[^#] mwlist.txt | cut -f1 -d ' ' | sort > mwlist-md5.txt  
#Generate checksums of all files in directory (eg. /etc)
find /etc -type f -print0 | xargs -0 md5sum > hash-etc.txt  
#Cut-out and sort MD5 checksums
cut -f1 -d ' ' hash-etc.txt | sort > hash-etc-md5.txt  
#Use comm to find common lines between the two files
comm -12 mwlist-md5.txt hash-etc-md5.txt  
#Output from Step 5 shows any matching checksums between my list and files in the chosen #directory. If not empty, identify individual file names with the following. Replace #EACH_LINE_IN_OUTPUT with those from Step 5's output:
grep "EACH_LINE_IN_OUTPUT" hash-etc.txt 


#Install Libreswan
#https://blog.ls20.com/ipsec-l2tp-vpn-auto-setup-for-ubuntu-12-04-on-amazon-ec2/
#https://github.com/hwdsl2/setup-ipsec-vpn
#Opened ports 500 and 4500 before running script
PSK:5e3dVWlwrkjZ7Qgx7f3Z
Username:vpnrsa
Password:rvPJ3z0pFA3JKG7
#Change IP tables in script from port 22 to 22713 for ssh
#If problems with openvpn after install run the following iptable rules then restart ufw and openvpn
sudo iptables -I INPUT -p udp --dport 1194 -j ACCEPT
sudo iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
sudo iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo service ufw stop
sudo service ufw start
sudo /etc/init.d/openvpn restart
#I remedied the above problems with iptables persistence by running the following commands. It is saved on backup 4 and we shouldn't have to run the commands anymore.
sudo iptables-save > /etc/iptables.rules
#Insert these lines in /etc/rc.local:
---------
#Load iptables rules from this file
iptables-restore < /etc/iptables.rules
--------

# Change DNS to own server
sudo nano /etc/openvpn/server.conf
push "dhcp-option DNS 104.236.123.185"
# push "dhcp-option DNS 8.8.8.8"
# push "dhcp-option DNS 8.8.4.4"
sudo /etc/init.d/openvpn restart

# We also changed this, but I don't think it matters for the VPN
sudo nano /etc/network/interfaces
sudo nano /etc/default/ufw
----
DEFAULT_INPUT_POLICY=“ACCEPT”
DEFAULT_FORWARD_POLICY=“ACCEPT”
----
# ufw limit 22
 
# What we used for the above
https://www.digitalocean.com/community/tutorials/how-to-configure-bind-as-a-caching-or-forwarding-dns-server-on-ubuntu-14-04








# OpenVPN and Ipsec L2tp server
Steps I take when setting up a VPN server on Digital Ocean

##Table of Contents
* [Create SSH Keys on client computer](#create-keys)
* [Login after creating droplet](#new-login)
* [Disable root login and change SSH port](#disable-root)
* [Enbale UFW](#enable-ufw)
* [Install OpenVPN](#install-ovpn)
* [Install Libreswan](#install-libreswan)
* [Install Dnsmasq](#dnsmasq)
* [Install NTP](#ntp)
* [Install send only SSMTP service](#ssmtp)
* [Enable Automatic Upgrades](#upgrades)
* [Setup fail2ban](#fail2ban)
* [Configure Tripwire](#tripwire)
* [Autostart OpenVPN on Debian client computer](#autostart)
* [Allow multiple clients to connect with same ovpn file](#multiple-clients)
* [Maintenance Commands](#misc)

### <a name="create-keys"></a>Create SSH Keys on client computer

Check for existing SSH keys

```bash
ls -al ~/.ssh
```

Generate new SSH key

```bash
ssh-keygen -t rsa -b 4096 -C your_email@example.com
```

Public key is now located in `/home/demo/.ssh/id_rsa.pub`. Private key is now located in `/home/demo/.ssh/id_rsa`. While creating new droplet, add these keys.

### <a name="new-login"></a>Login after creating droplet

Login as root

```bash
ssh root@server_ip_address
```

Upgrade system

```bash
sudo apt-get update && sudo apt-get upgrade && sudo apt-get dist-upgrade
```

Create new user

```bash
adduser demo
```

Give root privileges

```bash
gpasswd -a demo sudo
```

Add public key authentication for new user using client computer. Call new public key `id_rsa_demo`

```bash
ssh-keygen -t rsa -b 4096 -C your_email@example.com
```

Copy contents of public key by `CTRL-C` or `(cat ~/.ssh/id_rsa_demo.pub)`

Manually install public key on server

```bash
su - demo
mkdir .ssh
chmod 700 .ssh
```

Paste in public key while in nano

```bash
sudo nano .ssh/authorized_keys

chmod 600 .ssh/authorized_keys
```

Exit returns to root

```bash
exit
```

Login as new user

###<a name="disable-root"></a>Disable root login and change SSH port

It is possible to change SSH port to anything you like as long as it doesn't conflict with other active ports. Port 22 is written below, but any port can be used. **Allow new port in ufw rules below and restart ufw before restarting ssh**

```bash
sudo nano /etc/ssh/sshd_config

Port 22
PermitRootLogin without-password
reload ssh
sudo restart ssh
```

### <a name="enable-ufw"></a>Enable UFW
    
```bash    
ufw limit 22
ufw allow 1194/udp
ufw allow 500/udp
ufw allow 4500/udp
```

Change from DROP to ACCEPT

```bash
sudo nano /etc/default/ufw

DEFAULT_FORWARD_POLICY="ACCEPT"
```

Add these lines to the before.rules file

```bash
sudo nano /etc/ufw/before.rules

# START OPENVPN RULES
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]
# Allow traffic from OpenVPN client to eth0
-A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE
COMMIT
# END OPENVPN RULES
```

UFW rules should look similar to this

```bash
#Status: active
#Logging: on (low)
#Default: deny (incoming), allow (outgoing), allow (routed)
#New profiles: skip

#To                         Action      From
#--                         ------      ----
#22                         LIMIT IN    Anywhere
#1194/udp                   ALLOW IN    Anywhere
#500/udp                    ALLOW IN    Anywhere
#4500/udp                   ALLOW IN    Anywhere
#1194/udp (v6)              ALLOW IN    Anywhere (v6)
#22 (v6)                    LIMIT IN    Anywhere (v6)
#500/udp (v6)               ALLOW IN    Anywhere (v6)
#4500/udp (v6)              ALLOW IN    Anywhere (v6)
```

### <a name="install-ovpn"></a>Install OpenVPN

```bash
#https://github.com/Nyr/openvpn-install
```

```bash    
wget git.io/vpn --no-check-certificate -O openvpn-install.sh && bash openvpn-install.sh
```

Copy unified .ovpn to client computer

```bash
scp -P root@server_ip_address:client.ovpn Downloads/
```

### <a name="install-libreswan"></a>Install Libreswan

```bash
#https://blog.ls20.com/ipsec-l2tp-vpn-auto-setup-for-ubuntu-12-04-on-amazon-ec2/
#https://github.com/hwdsl2/setup-ipsec-vpn
```

```bash
wget https://github.com/hwdsl2/setup-ipsec-vpn/raw/master/vpnsetup.sh -O vpnsetup.sh
```

```bash
sudo nano -w vpnsetup.sh

PSK:your_private_key
Username:your_username
Password:your_password
```

```bash
/bin/sh vpnsetup.sh
```

Run following commands if OpenVPN doesn't work after reboot

```bash
sudo iptables -I INPUT -p udp --dport 1194 -j ACCEPT
sudo iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
sudo iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo service ufw stop
sudo service ufw start
sudo /etc/init.d/openvpn restart
```

Enable Iptables persistence so above commands should no longer be needed

```bash
sudo iptables-save > /etc/iptables.rules
```

Insert these lines in /etc/rc.local:

```bash
iptables-restore < /etc/iptables.rules
```

### <a name="dnsmasq"></a>Install Dnsmasq

Check current nameserver configuration

```bash
cat /etc/resolv.conf
```

Install Dnsmasq

```bash
sudo apt-get install dnsmasq
cat /etc/resolv.conf
```

Take note of query time

```bash
dig digitalocean.com @localhost
```

Check again after cached

```bash
dig digitalocean.com @localhost
```

### <a name="ntp"></a>Install NTP

```bash
sudo apt-get install ntp
```

```bash
sudo dpkg-reconfigure tzdata
sudo ntpdate pool.ntp.org
sudo service ntp start
```

### <a name="ssmtp"></a>Install send only SSMTP service

```bash
sudo apt-get install ssmtp
```

```bash
sudo nano /etc/ssmtp/ssmtp.conf

#root=postmaster
root=your_email@example.com
#mailhub=mail
mailhub=smtp.gmail.com:587
AuthUser=your_email@example.com
AuthPass=your_password
UseTLS=YES
UseSTARTTLS=YES
#rewriteDomain=
rewriteDomain=gmail.com
#hostname=your_hostname
hostname=your_email@example.com
```

Test ssmtp in terminal

```bash
ssmtp recipient_email@example.com
```

Format message as below:
```bash
To: recipient_email@example.com
From: myemailaddress@gmail.com
Subject: test email

test email
```

Insert blank line after `Subject:`. This is the body of the email. Press `CTRL-D` to send message. Sometimes I need to press `CTRL-D` a second time after about 10 seconds if the message is not sent.

### <a name="upgrades"></a>Enable Automatic Upgrades

```bash
sudo apt-get install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades
```

Update the 10 periodic file. `1` means that it will upgrade every day

```bash
sudo nano /etc/apt/apt.conf.d/10periodic

APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "1";
APT::Periodic::Unattended-Upgrade "1";
```

### <a name="fail2ban"></a>Setup fail2ban

```bash
sudo apt-get install fail2ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

```bash
sudo nano /etc/fail2ban/jail.local

# "ignoreip" can be an IP address, a CIDR mask or a DNS host. Use space separator to add more than one IP
ignoreip = 127.0.0.⅛
bantime  = 600
maxretry = 3

destemail = your_email@example.com
sendername = Fail2Ban
mta = sendmail
#_mwl sends email with logs
action = %(action_mwl)s
```

Jails which can be initially set to true without any errors

```bash
#ssh
#dropbear
#pam-generic
#ssh-ddos
#postfix
#couriersmtp
#courierauth
#sasl
#dovecot
```

Restart fail2ban

```bash
sudo service fail2ban stop
sudo service fail2ban start
```

Check list of banned IPs for fail2ban

```bash
fail2ban-client status ssh
iptables --list -n | fgrep DROP
```

###Full system backup using rsync.

Using the -aAX set of options, all attributes are preserved

```bash
rsync -aAXv --exclude={"/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found"} root@your_hostname:/ /home/demo/backup/
```

### <a name="tripwire"></a>Configure TripWire

```bash
#https://www.digitalocean.com/community/tutorials/how-to-use-tripwire-to-detect-server-intrusions-on-an-ubuntu-vps
```

```bash
sudo apt-get install tripwire
```

Set the `Site-Key` and `Local-Key` passphrase

Create policy file

```bash
sudo twadmin --create-polfile /etc/tripwire/twpol.txt
```

Initialize database

```bash
sudo tripwire --init
sudo sh -c 'tripwire --check | grep Filename > /etc/tripwire/test_results'
```

Entries may look like this

```bash
less /etc/tripwire/test_results
```

```bash
     Filename: /etc/rc.boot
     Filename: /root/mail
     Filename: /root/Mail
     Filename: /root/.xsession-errors
     Filename: /root/.xauth
     Filename: /root/.tcshrc
     Filename: /root/.sawfish
     Filename: /root/.pinerc
     Filename: /root/.mc
     Filename: /root/.gnome_private
     Filename: /root/.gnome-desktop
     Filename: /root/.gnome
     Filename: /root/.esd_auth
     Filename: /root/.elm
     Filename: /root/.cshrc
     Filename: /root/.bash_profile
     Filename: /root/.bash_logout
     Filename: /root/.amandahosts
     Filename: /root/.addressbook.lu
     Filename: /root/.addressbook
     Filename: /root/.Xresources
     Filename: /root/.Xauthority
     Filename: /root/.ICEauthority
     Filename: /proc/30400/fd/3
     Filename: /proc/30400/fdinfo/3
     Filename: /proc/30400/task/30400/fd/3
     Filename: /proc/30400/task/30400/fdinfo/3
```

Edit text policy in editor

```bash
sudo nano /etc/tripwire/twpol.txt
```

Search for each of the files that were returned in the `test_results` file. Comment out lines that match.

```bash
    {
        /dev                    -> $(Device) ;
        /dev/pts                -> $(Device) ;
        #/proc                  -> $(Device) ;
        /proc/devices           -> $(Device) ;
        /proc/net               -> $(Device) ;
        /proc/tty               -> $(Device) ;
        . . .
```

Comment out `/var/run` and `/var/lock` lines

```bash
    (
  rulename = "System boot changes",
  severity = $(SIG_HI)
    )
    {
        #/var/lock              -> $(SEC_CONFIG) ;
        #/var/run               -> $(SEC_CONFIG) ; # daemon PIDs
        /var/log                -> $(SEC_CONFIG) ;
    }
```

Save and close

Re-create encrypted policy file

```bash
sudo twadmin -m P /etc/tripwire/twpol.txt
```

Re-initialize database

```bash
sudo tripwire --init
```

Warnings should be gone. If there are still warnings, continue editing `/etc/tripwire/twpol.txt` file until gone.

Check current status of warnings

```bash
sudo tripwire --check
```

Delete `test_results` file that was just created

```bash 
sudo rm /etc/tripwire/test_results
```
Remove plain text configuration files

```bash    
sudo sh -c 'twadmin --print-polfile > /etc/tripwire/twpol.txt'
```

Move text version to backup location and recreate it

```bash
sudo mv /etc/tripwire/twpol.txt /etc/tripwire/twpol.txt.bak
sudo sh -c 'twadmin --print-polfile > /etc/tripwire/twpol.txt'
```

Remove plain text files

```bash
sudo rm /etc/tripwire/twpol.txt
sudo rm /etc/tripwire/twpol.txt.bak
```

Send an email notifications

```bash
sudo apt-get install mailutils
```

See if we can send email

```bash
sudo tripwire --check | mail -s "Tripwire report for `uname -n`" your_email@example.com
```

Check report that was sent with the email

```bash
sudo tripwire --check --interactive
```

Remove `x` from box if not ok with change. Re-run above command to reset warning after each email received

Automate Tripwire with Cron

Check if root already has crontab by issuing this command

```bash
sudo crontab -l
```

If crontab is present, pipe into file to back it up

```bash
sudo sh -c 'crontab -l > crontab.bad'
```

Edit crontab

```bash
sudo crontab -e
```

To have tripwire run at 3:30am every day, insert this line

```bash
30 3 * * * /usr/sbin/tripwire --check | mail -s "Tripwire report for `uname -n`" your_email@example.com
```

### <a name="autostart"></a>Autostart OpenVPN on Debian client computer

```bash
sudo nano /etc/default/openvpn
```

Uncomment:

```bash
AUTOSTART=all
```

Copy `client.ovp`n to `/etc/openvpn/client.conf` by renaming file

```bash
gksu -w -u root gksu thunar
```

Reload openvpn configuration

```bash
/etc/init.d/openvpn reload /etc/openvpn/client.conf
```

Check for `tun0` interface

```bash
ifconfig
```

### <a name="multiple-clients"></a>Allow multiple clients to connect with same ovpn file

Note: It is safer to create multiple ovpn files

```bash
sudo nano /etc/openvpn/server.conf
```

Uncomment following line:

```bash
duplicate-n
```

Restart OpenVPN service

```bash
sudo service openvpn restart
```

### <a name="misc"></a>Maintenance Commands

Programs holding open network socket

```bash
lsof -i
```

Show all running processes

```bash
ps -ef
```

Who is logged on

```bash
who -u
```

Kill the process that you want

```bash
kill "pid"
```

Check SSH sessions

```bash
ps aux | egrep "sshd: [a-zA-Z]+@"
```

Check SSHD

```bash    
ps fax
```

Check last logins

```bash
last
```

Check ufw status

```bash
sudo ufw status verbose
```

Delete ufw rules

```bash
sudo ufw delete deny "port"
```

Check logs

```bash
grep -ir ssh /var/log/* 
grep -ir sshd /var/log/* 
grep -ir breakin /var/log/* 
grep -ir security /var/log/*
```

Tree directory 

```bash
http://www.cyberciti.biz/faq/linux-show-directory-structure-command-line/
```

See all files

```bash
tree -a
```

List directories only

```bash
tree -d
```
Colorized output

```bash    
tree -C
```

File management

```bash
https://www.digitalocean.com/community/tutorials/basic-linux-navigation-and-file-management
http://www.computerworld.com/article/2598082/linux/linux-linux-command-line-cheat-sheet.html
http://www.debian-tutorials.com/beginners-how-to-navigate-the-linux-filesystem
```

LSOF Commands

```bash
https://stackoverflow.com/questions/106234/lsof-survival-guide
```

How to kill zombie process

```bash
ps aux | grep 'Z'
```

Find the parent PID of the zombie

```bash
pstree -p -s 93572
```

Check IPTables traffic

```bash
sudo iptables -v -x -n -L
```
Report file system disk space

```bash
df -Th
```

Check trash size

```bash
sudo find / -type d -name '*Trash*' | sudo xargs du -h | sort
```

Check size of packages in apt

```bash
du -h /var/cache/apt/
```

Check size of log files

```bash
sudo du -h /var/log
```

Check size of lost+found folder

```bash
sudo find / -name "lost+found" | sudo xargs du -h
```

How to delete lots of text in nano

```bash
Scroll to top of text, press Alt+A, Ctrl-V to bottom of text, press Ctrl-K to cut the text, Ctrl-O to save, Ctrl-X to exit
```

How to scan top 8000 ports using nmap

```bash
nmap -vv --top-ports 8000 your_hostname
```


