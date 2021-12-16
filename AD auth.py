from ldap3 import Server, Connection, ALL
import re
import boto3
import json
import os
import redis
import base64
import time
def lambda_handler(event,context):
	print("Calling elasticache xxxxxxxxxxxxxxxxxxxxx")
	r = redis.StrictRedis(host='<redis host>',charset="utf-8",port=6379,ssl_cert_reqs=None,decode_responses=False)
	print("Done executing the connection to elasticache -----")
	# Decrypt code should run once and variables stored outside of the function
	# handler so that these are decrypted once per container
	client= boto3.client('iam')
	#check if user is in cache
	username=event['username']+'<@yourdomain>'
	user=bytes(event['username'],'utf-8')
	encoded_user = base64.b64encode(user)
	print("Checking key")
	resp=r.hgetall(encoded_user)
	print("Done checking key")
	print(resp)
	password=event['password']
        #user not in cache
	if (not resp):
		#encrypt password
		stob=bytes(password,'utf-8')
		pb=base64.b64encode(stob)
		print("Encrypting password")
		ENCRYPTED_PASSWORD=boto3.client('kms',region_name='<your_region>').encrypt(KeyId="<your key id>",Plaintext=pb)
		print("Done encrypting")
		try:
			print("Connecting to AD")
			print(time.time())
			server = Server('<your AD FQDN>',get_info=ALL,port=3269,use_ssl=True)
			print("Establishing connection")
			print(time.time())
			conn = Connection(server, username, password, auto_bind=True)
			print("Connected")
			print(time.time())
			user=event['username']
			print("Searching")
			conn.search('dc=<yourdomain>,dc=<com>', '(&(objectClass=person)(objectClass=user)(objectClass=organizationalPerson)(CN='+user+'))', attributes=['memberOf'])
			#if (len(conn.entries) > 0 ):
			#	data=str(conn.entries)
			#else:
			#	conn.search('dc=americas,dc=astrazeneca,dc=net', '(&(objectClass=person)(objectClass=user)(objectClass=organizationalPerson)(CN='+user+'))', attributes=['memberOf'])
			#	if (len(conn.entries) > 0 ):
			#		data=str(conn.entries)
			#	else:
			#		conn.search('dc=emea,dc=astrazeneca,dc=net', '(&(objectClass=person)(objectClass=user)(objectClass=organizationalPerson)(CN='+user+'))', attributes=['memberOf'])        
			print("Done searching")
			data=str(conn.entries)
			groups=re.findall(r'<your AWS AD group<',data)
			role="arn:aws:iam::<AWS ACCT>:role/"+groups[0].split(',')[0]
			response = client.list_attached_role_policies(RoleName=groups[0].split(',')[0])
			arn=client.get_policy(PolicyArn=(response['AttachedPolicies'][0]['PolicyArn']))
			policy = client.get_policy(PolicyArn = arn['Policy']['Arn'])
			policy_version = client.get_policy_version(
			PolicyArn = arn['Policy']['Arn'], 
			VersionId = policy['Policy']['DefaultVersionId'])
			defpol=str(json.dumps(policy_version['PolicyVersion']['Document']))
			#add user info to cache
			print("Adding user to cache")
			r.hmset(encoded_user, {'CiphertextBlob':ENCRYPTED_PASSWORD['CiphertextBlob'],'role':role,'policy':defpol})
			r.expire(encoded_user,43200)
			print("Done adding")
			return{
				'statusCode':200,
				'Role':role,
				'Policy':defpol,
				'HomeDirectory':'/'
				
			}
		except:
			return{
				'statusCode':200,
				'Role':'',
				'Policy':' ',
				'HomeDirectory':''
		}
	else:
		print("Retrieving user data from cache")
		role_bytes=resp[b'role']
		policy_bytes=resp[b'policy']
		role=role_bytes.decode()		
		policy=policy_bytes.decode()
		#check password
		cipher=resp[b'CiphertextBlob']
		print("Decrypting password")
		DECRYPTED = boto3.client('kms',region_name='<your region>').decrypt(KeyId="<your key>",CiphertextBlob=cipher)
		print("Password decrypted")
		password_byte=base64.b64decode(DECRYPTED['Plaintext'])
		password_redis=password_byte.decode()
		if (password_redis == password):
			return{
				'statusCode':200,
				'Role':role,
				'Policy':policy,
				'HomeDirectory':'/'
				}
		else:
			return{
				'statusCode':200,
				'Role':'',
				'Policy':' ',
				'HomeDirectory':''
				}
			