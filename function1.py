import os
import sys
import subprocess
import datetime
from termcolor import colored
from datetime import datetime
import time
import nmap

user=['new1','Administrator','CCDAdmin','CCDuser']
passwd=['Infy@123','HelloWorld@123']
vuln=[]
ul=[]
dl=[]
count=0
ap=''
locationlog=open("LocationLog.txt","w+")
le=0
nullips=[]
then=datetime.now()
start=time.asctime(time.localtime(time.time()))
#f.writelines(start+"\n")
print(then)
locationlog.writelines("\n"+str(start)+"\n")
def alivehost(snet):
	print("started scan on  "+snet)
	pth=os.getcwd()
	snets=snet.split("/")[0]+"-"+snet.split("/")[1]
	path1=os.path.join(pth,snets)
	os.mkdir(path1)
	path2="LiveHosts.txt"
	path3=os.path.join(path1,path2)
	f=open(path3,'w')
	path4="BadHosts.txt"
	path5=os.path.join(path1,path4)
	f1=open(path5,'w')
	"""path6="Logs.txt"
	path7=os.path.join(path1,path6)
	lg=open(path7,"w+")"""
	then=datetime.now()
	#lg.writelines("\n"+str(then)+"\n")
	command= snet+" 2>/dev/null"
	cmd= ['fping', '-g', command]
	sub = subprocess.Popen(cmd, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
	locationlog.writelines("-----------------------------------------")	
	print("\nStarting Segment spraying for .."+snet+"\n")
	locationlog.writelines("\nStarting Segment spraying for .."+snet+"\n")
	locationlog.writelines("-----------------------------------------")
	for line in sub.stdout:
            line=line.strip()
	    global le
	    le=le+1
            ip = line.split(" ",1)[0]
	    if "is alive" in line:
	    	ul.append(ip)
		#f.writelines("\n")
		f.writelines(ip+"\n")
	
	    elif "is unreachable" in line:
	    	dl.append(ip)
		#f1.writelines("\n")
		f1.writelines(ip+"\n")
	msg1="\nFound "+str(len(ul))+" Machines Alive Out of "+str(le)+"\n"
	locationlog.writelines(msg1)
	f.writelines("\n")
	f.close()
	f1.writelines("\n")
	f1.close()
	#lg.close()
	print(msg1)
	sub.stdout.close()
def sessions(command1,smbip,cred0,cred1,snet):
	global count					
	count+=1
	thn=datetime.now()
	print(command1)
	sub = subprocess.Popen(command1, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE, close_fds=True)
	for l in sub.stdout:
		if l.startswith('[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid'):
			print colored(""+smbip+"Bad Credentials "+cred0+" "+cred1+"\n",'blue')
			#lg.writelines("\n"+smbip+"--"+"Bad Credentials"+"\n")
		elif l.startswith('Connection Established pa..'):
			print colored("Successfully Logged into  "+smbip+"\n",'red')
			#lg.writelines("\n"+smbip+"--"+ "Login Successful with "+smbip+" with "+cred0+" "+cred1+"\n")
			communication=" "+smbip+" -- Login Details: "+""+cred0+" with "+cred1
		        vuln.append(communication)
		#lg.close()
	sub.stdout.close()

def communications(live,subnet):
	if not live=="":
		nm=nmap.PortScanner()
		nm.scan(live,'139,445')

		if nm[live]['tcp'][139]['state']=='open' or nm[live]['tcp'][445]['state']=='open':
			print("\nSMB port is Open... \n")
			ap=live
			msg2="Connecting to "+ap+"\n"
			print(msg2)
			#f.writelines("\n"+msg2)
			for p in passwd:
				for u in user:
					target_ip= u+":"+p+"@"+ap 
					print(target_ip)
					cmd= ['python','myclient.py', target_ip]
					cmd2=['python','myclient.py', ap]
					sessions(cmd,ap,u,p,subnet)

systems=sys.argv[1]

snet=[]

system=open(systems,"r")
all=0
attempt=0
for subnet in system:
	sunet=subnet.strip()
	snet.append(sunet)
	#print("checking for"+sunet)
	alivehost(sunet)
	pth=os.getcwd()
	snets=sunet.split("/")[0]+"-"+sunet.split("/")[1]
	path1=os.path.join(pth,snets)
	path2="LiveHosts.txt"
	path3=os.path.join(path1,path2)
	f=open(path3,'r')
	true_details=[]
	for ip in f.readlines():
		#print("entering to nmap scan")
		liveip=ip.rstrip("\n")
		communications(liveip,subnet)
	all+=len(ul)
	attempt+=count
	count=0	
	ul=[]
	le=0
	f.close()

system.close()
now=datetime.now()
dur=now-then
dur_s=dur.total_seconds()
hours=divmod(dur_s,3600)[0]
minutes=divmod(dur_s,60)[0]

print colored("\nSuccessfully covered "+str(all)+" machines in entire " +"ip segment with "+str(attempt)+" Login attempts in"+str(hours)+" hours, "+str(minutes)+" minutes.\n",'green')
locationlog.writelines("\nSuccessfully covered "+str(all)+" machines in entire " +"ip segment with "+str(attempt)+" Login attempts in"+str(hours)+" hours, "+str(minutes)+" minutes.\n")
cls=time.asctime(time.localtime(time.time()))

for v in vuln:
	
	print colored(v+"\n",'yellow')
	locationlog.writelines(v+"\n")
locationlog.writelines("\n"+cls+"\n")
