
from inspect import getsourcefile
from os.path import abspath
import os
import sys
import re
import string
import glob
import socket
from FileImageWorker.FileWorker import FileFinder
import ipaddress
from pathvalidate import ValidationError, validate_filepath
import validators
import collections,operator
import math, datetime,calendar


def convert_time_to_seconds(time:str):
        if time!=None:
            try:
                date = datetime.datetime.strptime(time, '%Y-%m-%d %H:%M:%S')
            except:
                date = datetime.datetime.strptime(time, '%Y-%m-%dT%H:%M:%S')
            dt1 = datetime.datetime.timetuple(date)
            cal = calendar.timegm(dt1)
            return cal
        else:
            return None


def remove_old_dumps():
     path = os.path.abspath(os.path.dirname(sys.argv[0]) )
     files = glob.glob(f'{path}\proc_dumps\*')
     for f in files:
          os.remove(f)


def diff_of_db(db:list,lst_proc:list):
     for proc in lst_proc:
          if proc.pid!="UserAssistPotentialProc":
               new_app=[]
               for db_ind in db:
                    new_dict={}
                    val = float(0)
                    if proc.db_dict['name']==db_ind['name']:
                         val=val+0.11
                         name=1
                    if proc.db_dict['file_action']==db_ind['file_action']:
                         val=val+0.11
                         fileact=1
                    if proc.db_dict['hide']==db_ind['hide']:
                         val=val+0.11
                         hide=1
                    if proc.db_dict['dlls'] and db_ind['dlls']:
                         num=0
                         len_db=len(db_ind['dlls'])
                         for i in proc.db_dict['dlls']:
                              if i in db_ind['dlls']:
                                   num = num + 1
                         itog=(float(num/len_db))*0.11
                         val=val+itog
                         dlls=1
                    elif proc.db_dict['dlls']==[] and db_ind['dlls']==[]:
                         val = val + 0.11
                         dlls=1
                    if proc.db_dict['cmd_line']==db_ind['cmd_line']:
                         val=val+0.11      
                         cmd=1
                    else:
                         cmd=0
                    if proc.db_dict['malfind']==db_ind['malfind']:
                         val=val+0.11  
                         mal=1  
                    if proc.db_dict['connections'] and db_ind['connections']:
                         num=0
                         len_db=len(db_ind['connections'])
                         for i in proc.db_dict['connections']:
                              if i in db_ind['connections']:
                                   num = num + 1
                         itog=(float(num/len_db))*0.11
                         val=val+itog
                         conn=1
                    elif proc.db_dict['connections']==[] and db_ind['connections']==[]:
                         val = val + 0.11  
                         conn=1
                    if proc.db_dict['files'] and db_ind['files']:
                         num=0
                         len_db=len(db_ind['files'])
                         for i in proc.db_dict['files']:
                              if i in db_ind['files']:
                                   num = num + 1
                         itog=(float(num/len_db))*0.11
                         val=val+itog
                         files=1
                    elif proc.db_dict['files']==[] and db_ind['files']==[]:
                         val = val + 0.11 
                         files=1
                    else:
                         files=0
                    if proc.db_dict['domains'] and db_ind['domains']:
                         num=0
                         len_db=len(db_ind['domains'])
                         for i in proc.db_dict['domains']:
                              if i in db_ind['domains']:
                                   num = num + 1
                         itog=(float(num/len_db))*0.11
                         val=val+itog
                         domains=1
                    elif proc.db_dict['domains']==[] and db_ind['domains']==[]:
                         val = val + 0.11  
                         domains=1
                    if val>=0.80:
                         new_app.append({'id':str(db_ind['_id']), \
                                         'name':db_ind['name'], \
                                         'sum_val':math.ceil(val*100), \
                                         'fa':"Yes" if fileact==1 else "None", \
                                         'hide': "Yes" if hide==1 else "None", \
                                         'dlls':"Yes" if dlls==1 else "None" , \
                                         'cmd': "Yes" if cmd==1 else "None", \
                                         'conn': "Yes" if conn==1 else "None", \
                                         'mal':"Yes" if mal==1 else "None", \
                                         'files': "Yes" if files==1 else "None", \
                                         'domains':"Yes" if domains==1 else "None" })                     
                         #new_dict[db_ind['name']]=math.ceil(val*100)
               newlist = sorted(new_app, key=lambda k: k['sum_val'], reverse=True) 
               proc.diff_dict=newlist







def check_proccesses_on_hide(non_hiden_proccesses:list,all_proccesses:list):
   list_pid=[]
   for elem in non_hiden_proccesses:
        list_pid.append(elem['PID'])
   for i in range(len(all_proccesses)):
        if(all_proccesses[i].pid not in list_pid):
            all_proccesses[i].hiden="Yes"

def check_proccesses_on_malfind(all_proccesses:list,malfind:list):
     for proc in range(len(all_proccesses)):
          for mal in malfind:
               if all_proccesses[proc].pid==mal['PID']:  all_proccesses[proc].malfind_date=mal

def check_netscan(all_proccesses:list,netlist:list):
     for proc in range(len(all_proccesses)):
          list_domain=[]
          list_proc=[]
          for net in netlist:
               if all_proccesses[proc].pid==net['PID']: 
                    list_proc.append(net)
          all_proccesses[proc].net_list = list_proc
          all_proccesses[proc].domain_list=check_domain(list_proc)



def exports_dumps_process(name_dump:str,lst_proc:list):
     path = os.path.abspath(os.path.dirname(sys.argv[0]) ) 
     os.system(f"python {path}\\volatility3-develop\\vol.py -o {path}\\proc_dumps -f {path}\\upload\\{name_dump} windows.psscan.PsScan --dump") 
     directory = os.listdir(f'{path}\\proc_dumps')
     if(len(directory))==0:
          os.system(f"python {path}\\volatility3-develop\\vol.py -o {path}\\proc_dumps -f {path}\\upload\\{name_dump} windows.pslist.PsList --dump")
          directory = os.listdir(f'{path}\\proc_dumps')
     for proc in range(len(lst_proc)):
          for dmp in range(len(directory)):
               if re.search(r"\b"+str(lst_proc[proc].pid)+r"\b",directory[dmp]):
                    lst_proc[proc].dumpfile = f'{path}\\proc_dumps\\{directory[dmp]}'

def strings(filename, min=4):
    with open(filename, errors="ignore") as f:  
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:
            yield result

def exports_strings_process(lst_proc:list):
     #file_func=['Create','create','write','Write']
     file_func=['CreateFile','CreateFileA','CreateFileW','CreateFile2','WriteFile','WriteFileEx','WriteFileGather']
     for proc in range(len(lst_proc)):
          stringss=[]
          if (lst_proc[proc].dumpfile!=None) and os.path.isfile(lst_proc[proc].dumpfile):
               for str in strings(lst_proc[proc].dumpfile,4):
                    stringss.append(str)
                    for keys in file_func:
                         if str in keys:
                              lst_proc[proc].check_func_file="Подтверждено взаимодействие с файлами"

          lst_proc[proc].strings=stringss
     #remove_old_dumps()

def find_artifacts_in_dump(lst_proc:list):
     find_domain = r'https?://[\S][^>]+'
     #Поиск адресов с портами
     find_ip_with_port =r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d{1,5}\b'
     #Поиск адресов без портов
     find_ip = r'\d{1,3}(?:\.\d{1,3}){3}$'
     # Поиск файлов и путей
     find_paths = r'[a-zA-Z]:\\((?:[a-zA-Z0-9() ]*\\)*).*'

     for proc in range(len(lst_proc)):
          path_artifacts=[]
          hosts_artifacts=[]
          domain_artifacts=[]
          if (lst_proc[proc].dumpfile!=None) and os.path.isfile(lst_proc[proc].dumpfile):
               for str in strings(lst_proc[proc].dumpfile,4):
                    find_path=re.search(find_paths,str)
                    find_domains=re.search(find_domain,str)
                    find_ips=re.search(find_ip,str)
                    find_ips_ports=re.search(find_ip_with_port,str)
                    if find_path:
                         if check_path(find_path[0]):
                              path_artifacts.append(find_path[0])
                    elif find_domains:
                         if check_url(find_domains[0]):
                              domain_artifacts.append(find_domains[0])
                    elif find_ips:
                         if check_ip(find_ips[0]):
                              hosts_artifacts.append(find_ips[0])
                    elif find_ips_ports:
                         hosts_artifacts.append(find_ips_ports[0])
          lst_proc[proc].path_artifacts=path_artifacts
          lst_proc[proc].hosts_artifacts=hosts_artifacts
          lst_proc[proc].domain_artifacts=domain_artifacts

def check_ip(ip:str):
     if validators.ip_address.ipv4(ip):
          return True
     else:
          return False

def check_url(url:str):
     if validators.url(url):
          return True
     else:
          return False

def check_path(path:str):
     try:
          validate_filepath(path)
          return True
     except ValidationError as e:
          return False  


def check_domain(netlist:list):
     list_domain = []
     domain_dict={}
     for item in netlist:
          if item['ForeignAddr']!="*" and item['ForeignAddr']!='0.0.0.0' and item['ForeignAddr']!=None and item['Proto']!='TCPv6':
               try:
                    find_domain = socket.gethostbyaddr(item['ForeignAddr'])
                    domain_dict['Address'] = item['ForeignAddr']
                    domain_dict['Domain'] = find_domain[0]
                    domain_dict['Create Time'] = item['Created']
                    list_domain.append(domain_dict)
               except socket.herror:
                    domain_dict['Address'] = item['ForeignAddr']
                    domain_dict['Create Time'] = item['Created']
                    domain_dict['Domain'] = "Не найден"
                    list_domain.append(domain_dict)
          domain_dict={}
     out = []
     for i in list_domain:
          if i not in out:
               out.append(i)
     return out