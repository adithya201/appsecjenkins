import urllib, urllib2
import sys
import os
import requests
import urllib

appName = sys.argv[1]
appID = "89c5ad4d1c7e367e23c257123ffe96e7"
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwib3JpZ19pYXQiOjE1MzM2MjY3NjEsInVzZXJfaWQiOjQsImVtYWlsIjoiIiwiZXhwIjoxNTMzNzEzMTYxfQ.GnNDGcAvCgLTXF8eyKnPd3lbwXU0opNIqVRxeSXkNug"

token = str(token).strip()
appID = str(appID).strip()

url = 'https://appsecure.accenture.com/api/scan_binary/'

path = os.environ['JENKINS_HOME']+'/jobs/'+os.environ['JOB_NAME']+'/workspace/'+appName

files = {'binaryFile': open(path,'rb')}

values = {
		  'Uid' : appID,
           }

authtoken = "JWT "+str(token)

headers = { "Authorization" : authtoken }

response = requests.post(url, data=values,files=files,headers=headers)

print response.json()
data = response.json()

if data['status'] == 'Failed':
	print " Build Failed - "+str(data['error'])+" !"
	exit(1)

x = str(data['message']).split("=")
x = x[1]

checkurl = 'https://appsecure.accenture.com/api/executive_report/'
values = {'appId' : x, }
authtoken = "JWT "+str(token)
headers = { "Authorization" : authtoken }
response = requests.post(checkurl, data=values,headers=headers)
x = response.json()
vuldetail =  x["vulnerabilitiesSummary"]
issuefound =  len(vuldetail)
highissues = 0
mediumissues = 0 
lowissues = 0 
while issuefound:
	severity =  vuldetail[str(issuefound)]["severity"]
	if severity == "High":
		highissues = highissues+1
	if severity == "Low":
		lowissues = lowissues+1
	if severity == "Medium":
		mediumissues = mediumissues+1	
	issuefound = issuefound - 1 
if highissues > 5:
	print "Build Failed because "+str(highissues)+" high security issues detected in your application! "
	exit(1)
if highissues >=3 and mediumissues >=3:
	print "Build Failed because "+str(highissues)+" high security issues and " +str(mediumissues)+" medium security issues detected in your application! " 
	exit(1)
print "Your Application has "+str(highissues)+ " high issues, "+str(mediumissues)+" medium issues, "+str(lowissues)+" low issues. "