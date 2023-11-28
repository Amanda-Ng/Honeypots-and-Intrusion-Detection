import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import maxminddb
import json

honeypotDataFile = '/home/amandan/ssh_23_09_21.json' # Enter the path to your data file here

honeypotActions = []
with open(honeypotDataFile, 'r') as inputFile:
    for line in inputFile:
        honeypotActions.append(json.loads(line))

honeypotData = pd.read_json(json.dumps(honeypotActions))
honeypotData.head()
uniqueActions = list(honeypotData['msg'].unique())
print('Unique actions recorded by the honeypot: ', end='')
for action in uniqueActions:
    print(action, end=', ')
honeypotConnections = honeypotData.loc[honeypotData['msg'] == 'Connection']
honeypotLogins = honeypotData.loc[honeypotData['msg'] == 'Request with password']
honeypotLoginKeys = honeypotData.loc[honeypotData['msg'] == 'Request with key']
numConnections = len(honeypotConnections)      # Fill in with a function call that returns the length of this dataframe
numLoginAttempts = len(honeypotLogins)    # Fill in with a function call that returns the length of this dataframe
numLoginKeyAttempts = len(honeypotLoginKeys) # Fill in with a function call that returns the length of this dataframe

print('Number of connections: %d' % numConnections)
print('Number of login attempts: %d' % numLoginAttempts)
print('Number of login attempts with a key: %d' % numLoginKeyAttempts)

has_login_key_attempts = numLoginKeyAttempts > 0
usernameFreq = honeypotLogins['duser'].value_counts()
passwordFreq = honeypotLogins['password'].value_counts()

topNToDisplay = 5

display(pd.DataFrame(usernameFreq.head(n=topNToDisplay)))
display(pd.DataFrame(passwordFreq.head(n=topNToDisplay)))

if has_login_key_attempts:
    keyFreq = honeypotLoginKeys['fingerprint'].value_counts()
    display(pd.DataFrame(keyFreq.head(n=topNToDisplay)))
usernameAttackerFreq = pd.DataFrame(honeypotLogins.groupby(['duser'])['src'].nunique().sort_values(ascending=False))
passwordAttackerFreq = pd.DataFrame(honeypotLogins.groupby(['password'])['src'].nunique().sort_values(ascending=False))

topNToDisplay = 5

display(usernameAttackerFreq.head(n=topNToDisplay))
display(passwordAttackerFreq.head(n=topNToDisplay))

if has_login_key_attempts:
    keyAttackerFreq = pd.DataFrame(honeypotLoginKeys.groupby(['fingerprint'])['src'].nunique().sort_values(ascending=False))
    display(keyAttackerFreq.head(n=topNToDisplay))
# Here we get the number of unique IP addresses as a basic measure of the number of attackers
numUniqueAttackers = len(honeypotLogins['src'].unique())

# We can use the apply() function of Pandas to pass each element of a column to a function and set the output to a new column
usernameAttackerFreq['percentage'] = usernameAttackerFreq['src'].apply(lambda x: '%.2f%%' % (x / numUniqueAttackers * 100))
passwordAttackerFreq['percentage'] = passwordAttackerFreq['src'].apply(lambda x: '%.2f%%' % (x / numUniqueAttackers * 100))

topNToDisplay = 5

display(usernameAttackerFreq.head(n=topNToDisplay))
display(passwordAttackerFreq.head(n=topNToDisplay))

if has_login_key_attempts:
    numUniqueKeyAttackers = len(honeypotLoginKeys['src'].unique())
    keyAttackerFreq['percentage'] = keyAttackerFreq['src'].apply(lambda x: '%.2f%%' % (x / numUniqueKeyAttackers * 100))
    display(keyAttackerFreq.head(n=topNToDisplay))
# Here we group our login data by each IP address and count the number of distinct user names and passwords in each group
ipUsernameFreq = honeypotLogins.groupby(['src'])['duser'].nunique().sort_values(ascending=False)
ipPasswordFreq = honeypotLogins.groupby(['src'])['password'].nunique().sort_values(ascending=False)

topNToDisplay = 5

display(pd.DataFrame(ipUsernameFreq.head(n=topNToDisplay)))
display(pd.DataFrame(ipPasswordFreq.head(n=topNToDisplay)))

if has_login_key_attempts:
    ipKeyFreq = honeypotLoginKeys.groupby(['src'])['fingerprint'].nunique().sort_values(ascending=False)
    display(pd.DataFrame(ipKeyFreq.head(n=topNToDisplay)))
# Here we're getting the number of login attempts per IP address using the value_counts() function on the source IP
# address column
numAuthTriesPerIP = honeypotLogins['src'].value_counts()

fig, ax = plt.subplots(figsize=(8, 4))

ax.hist(numAuthTriesPerIP, cumulative=True, density=True, bins=50, histtype='step')

plt.xlabel('Number of Login Attempts')
plt.ylabel('Percentage of Attackers')
plt.show()
reader = maxminddb.open_database('GeoLite2-City.mmdb')
reader.get('8.8.8.8')
def getCountryName(ip):
    locationData = reader.get(ip)
    
    # In the cases where the IP address' location can't be determined, we return an empty string
    if(locationData is None or 'country' not in locationData):
        return ''
    
    return locationData['country']['names']['en']

honeypotConnections = honeypotConnections.copy()
honeypotConnections['country'] = honeypotConnections['src'].apply(lambda ip: getCountryName(IP))
topNToDisplay = 5

numConnectionsPerCountry = honeypotConnections['country'].value_counts()

display(numConnectionsPerCountry.head(n = topNToDisplay))
