# Pneumatic Tube System User Upload Poster
# Posts an upload file of users to the data logger
# Retrieves upload files from d:\xxx
# By MS Technology Solutions LLC
# For Colombo Pneumatic Tube Systems Inc
#
# History:
# v1.00     02-Nov-2014  Initial Release
version = 'auto_upload_users.py version 1.00 02-Nov-14'
#
import requests
import smtplib
from email.mime.text import MIMEText
from email.utils import COMMASPACE
url = 'http://localhost/pts/web/app.php/autoupload'
###files = {'myfile': open('Associates.csv', 'rb')}
files = {'myfile': open('d:\AssociateData\Associates.csv', 'rb')}
params = {'header': 1, 'spam': 1}
r = requests.post(url, files=files, data=params)

# print result to the screen
print r.text

# email result to a recipient
msg = MIMEText(r.text)

me = 'TubeServer@colombopts.com'
# multiple names can be comma space separated
you = ["ms48083@netscape.net", "joe@colombopts.com", "mikes@colombopts.com", "Todd.Tittle@UCHealth.com"]
msg['Subject'] = 'Pneumatic Tube System Status'
msg['From'] = me
msg['To'] = COMMASPACE.join(you)

# Send the message via the SMTP server
s = smtplib.SMTP('mail.healthall.com')
s.sendmail(me, you, msg.as_string())
