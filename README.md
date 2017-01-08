# OpenVPN and Ipsec L2tp server
Steps I take when setting up a VPN server on Digital Ocean

##Table of Contents
* [Create SSH keys on client computer](#create-keys)
* [Login after creating droplet](#new-login)
* [Disable root login and change SSH port](#disable-root)
* [Enbale UFW](#enable-ufw)
* [Install OpenVPN](#install-ovpn)
* [Install Libreswan](#install-libreswan)
* [Install Dnsmasq](#dnsmasq)
* [Install NTP](#ntp)
* [Install send only SSMTP service](#ssmtp)
* [Install Fail2ban](#fail2ban)
* [Install Tripwire](#tripwire)
* [Enable Automatic upgrades](#upgrades)
* [Autostart OpenVPN on Debian client computer](#autostart)
* [Allow multiple clients to connect with same ovpn file](#multiple-clients)
* [Maintenance commands](#misc)

### <a name="create-keys"></a>Create SSH keys on client computer

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

Add these lines to the `before.rules` file

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

Copy unified `.ovpn` to client computer

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

sudo iptables-save > /etc/iptables.rules
```

```bash
sudo nano /etc/rc.local

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
dig duckduckgo.com @localhost
```

Check again after cached

```bash
dig duckduckgo.com @localhost
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

Format message as below

```bash
To: recipient_email@example.com
From: myemailaddress@gmail.com
Subject: test email

test email
```

Insert blank line after `Subject:`. This is the body of the email. Press `CTRL-D` to send message. Sometimes pressing `CTRL-D` a second time after about 10 seconds is needed if message is not sent.

### <a name="fail2ban"></a>Install Fail2ban

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

Restart Fail2ban

```bash
sudo service fail2ban stop
sudo service fail2ban start
```

Check list of banned IPs for Fail2ban

```bash
fail2ban-client status ssh
iptables --list -n | fgrep DROP
```

###Full system backup using rsync.

Using the -aAX set of options, all attributes are preserved

```bash
rsync -aAXv --exclude={"/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found"} root@your_hostname:/ /home/demo/backup/
```

### <a name="tripwire"></a>Install TripWire

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

```bash
#Programs holding open network socket
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

#Tree directory 
http://www.cyberciti.biz/faq/linux-show-directory-structure-command-line/

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
Scroll to top of text, press Alt+A, Ctrl-V to bottom of text, press Ctrl-K to cut the text, Ctrl-O to save, Ctrl-X to exit

#How to scan top 8000 ports using nmap
nmap -vv --top-ports 8000 your_hostname

#Delete ufw and iptable rules by line number. In this example we use number 666
sudo ufw status numbered
sudo ufw delete 666

sudo iptables -L --line-numbers
sudo iptables -D INPUT 666
```
