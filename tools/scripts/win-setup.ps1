wget http://cygwin.com/setup-x86_64.exe -OutFile setup.exe
Start-Process -FilePath ".\setup.exe" -ArgumentList "-q -P wget,tar,qawk,bzip2,subversion,vim,make,gcc-g++,diffutils,libgmp-devel,libmpfr-devel,libmpc-devel,libisl-devel,openssh,cygrunsrv,syslog-ng" -Wait

#wget https://gallery.technet.microsoft.com/scriptcenter/Add-Adminps1-powershell-4cc04875/file/128446/1/Add-Admin.ps1 -OutFile Add-Admin.ps1
#. ".\Add-Admin.ps1"

#$syspath = [System.Environment]::GetEnvironmentVariable("path", "Machine")
#$syspath = "$syspath;C:\cygwin64\bin"

#[System.Environment]::SetEnvironmentVariable("path", "$syspath", "Machine")

#Add-Admin -ComputerName $env:COMPUTERNAME -NewAdmin sshd

#C:\cygwin64\bin\bash -c /bin/ssh-host-config -y -N sshd -u sshd -w password


#!/bin/bash

/usr/bin/chmod +r /etc/passwd
/usr/bin/chmod u+w /etc/passwd
/usr/bin/chmod +r /etc/group
/usr/bin/chmod u+w /etc/group
/usr/bin/chmod 755 /var
/usr/bin/touch /var/log/sshd.log
/usr/bin/chmod 664 /var/log/sshd.log

# this presumedly could be done in powershell, however
# the chmod'ing is probably easier done in bash
/usr/bin/editrights -l -u sshd
/usr/bin/editrights -a SeAssignPrimaryTokenPrivelege -u sshd
/usr/bin/editrights -a SeCreateTokenPrivelege -u sshd
/usr/bin/editrights -a SeTcbPrivelege -u sshd
/usr/bin/editrights -a SeServiceLogonRight -u sshd
/usr/bin/editrights -l -u sshd

/usr/bin/ssh-host-config -y -N sshd -u sshd -w password
