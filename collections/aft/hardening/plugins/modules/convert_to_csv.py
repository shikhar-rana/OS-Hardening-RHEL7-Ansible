from __future__ import(absolute_import, division, print_function)
__metaclass__ = type
 
 
 
DOCUMENTATION = ''' #'''
EXAMPLES = ''' # '''
 
import os
import csv
import json
 
from ansible.module_utils.basic import AnsibleModule
module=AnsibleModule(argument_spec={'output_file_path': {'required' : True, 'type' : 'str'}})
output_path = module.params['output_file_path']
 
def main():
    csv_data=[]
    csv_data.append(['Server Name','Serial No','Parameter','Status'])
 
    for (root, dirs, files) in os.walk(output_path, topdown=True):
        for Servername in dirs:
            with open(output_path + '/' +  Servername + '/output.json') as json_data:
                data = json.load(json_data)
       
            headers = list(data.keys())
            for i in headers:
                for j in data[i].keys():
                    x=data[i][j]
                    t_list=[]
                    if(str(type(x)) == "<class 'dict'>"):
                        t=list(x.values())
                        if(len(t)==4):
                            t_list.append(Servername)
                            t_list.append(j)
                            t_list.append(t[1])
                            t_list.append(t[2])
                            csv_data.append(t_list)
                        elif(len(t)==6):
                            t_list.append(Servername)
                            t_list.append(j)
                            t_list.append(t[1])
                            t_list.append(t[4])
                            csv_data.append(t_list)
                           
    with open(output_path + "/Red_Hat_Enterprise_Linux_7_Benchmark_Scored_report.csv", "w", newline="") as f:
       writer = csv.writer(f)
       writer.writerows(csv_data)
  
    if(len(csv_data)!=0):
        module.exit_json(changed='True')
    else:
        msg = "Failed"
        module.fail_json(msg=msg)
 
 
if __name__ == '__main__':
    main()         
 
 