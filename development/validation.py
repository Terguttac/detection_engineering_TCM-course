import tomllib
import sys
import os


failure = 0

for root, dirs, files in os.walk('detections/'):
	for file in files:
		if file.endswith('.toml'):
			full_path = os.path.join(root, file)
			with open(full_path,'rb') as toml:
				alert = tomllib.load(toml)	

				if alert['rule']['type'] == 'query': # query based alert
					required_fields = ['description','name','rule_id','risk_score','severity','type','query']
				elif alert['rule']['type'] == 'eql': # event correlation alert
					required_fields = ['description','name','rule_id','risk_score','severity','type','query', 'language']
				elif alert['rule']['type'] == 'threshold': # threshold based alert
					required_fields = ['description','name','rule_id','risk_score','severity','type','query', 'threshold']
				else:
					print('Invalid rule type:', alert['rule']['type'], 'in ', full_path)
					break

				present_fields = []
				missing_fields = []

				for field in alert['rule']:
					present_fields.append(field)

				for field in required_fields:
					if field not in present_fields:
						missing_fields.append(field)

				if missing_fields:
					print("The following fields do not exist in", file + ":", str(missing_fields))
					failure = 1
				else:
					print(file, '- passed the validation check')

if failure != 0:
	sys.exit(1)