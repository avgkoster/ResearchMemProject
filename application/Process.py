from typing import List
import socket
import os,sys
from datetime import date, datetime
import json
import calendar
from utilities.utilities import convert_time_to_seconds

class Process:




#test

    def __init__(self,name:str,pid:int,str_time,end_time,dlls:dict,path=None,cmd=None,system_time=None,interval=int(0)):
        print(interval)
        self.diff_dict=[]
        self.global_graph=[]
        self.dumpfile = None
        self.files_graph=[]
        self.hiden = None
        self.strings=[]
        self.check_func_file="Не обнаружено"
        self.malfind_date={}
        self.net_list=[]
        self.path_artifacts=[]
        self.hosts_artifacts=[]
        self.domain_artifacts=[]
        self.domain_list=[]
        self.interval=[]
        self.files_on_images=[]
        self.net_graph=[]
        self.dll_graph=[]
        self.pid=pid
        self.systime=system_time
        self.name=name
        self.str_time=str_time
        self.end_time=end_time
        self.path=path
        self.dlls=self.check_dlls(dlls)
        self.time_dlls=self.check_time_dlls(dlls)
        self.cmd=self.check_cmd(cmd)
        if interval:
            self.time_interval=[convert_time_to_seconds(self.str_time), \
            convert_time_to_seconds(self.str_time)+int(interval)]
        else:
            self.time_interval=[convert_time_to_seconds(self.str_time), \
            convert_time_to_seconds(self.systime)]
        

    def check_time_dlls(self,dll_dict:dict):
        dll_time_list=[]
        for unit in dll_dict:
            if self.pid==unit['PID']:
                dll_time_list.append({'name':unit['Path'],'time':unit['LoadTime']})
        return dll_time_list


    def check_dlls(self,dll_dict:dict):
        dll_list=[]
        for unit in dll_dict:
            if self.pid==unit['PID']:
                dll_list.append(unit['Path'])
        if self.pid!='UserAssistPotentialProc':
            if dll_list:
                self.path=dll_list[0]
        return dll_list

    def check_cmd(self,cmd_dict):
        cmd_line=""
        if cmd_dict:
            for item in cmd_dict:
                if self.pid==item['PID']:
                    cmd_line=item['Args']
            return cmd_line
        else:
            return None        
                





    def generate_text_report(self):
        time_report = datetime.now().strftime("%d_%m_%Y")
        file_name=str(self.pid)+'_'+self.name.split('|')[0]+'_'+time_report+'.txt'
        path = os.path.abspath(os.path.dirname(sys.argv[0]) )
        with open(f"{path}\\reports\\{file_name}","w") as report_file:
            report_file.write("Отчет сканирования процесса\n\nИмя процесса:\n")
            report_file.write(self.name.split('|')[0]+'\n\n')
            report_file.write("PID Процесса:\n")
            report_file.write(str(self.pid)+'\n\n')
            report_file.write("Расположение процесса:\n")
            if self.path:
                report_file.write(self.path+'\n\n')
            else:
                report_file.write("Не найден\n\n")
            report_file.write("Время запуска:\n")
            report_file.write(str(self.str_time)+'\n\n')
            report_file.write("Скрытый:\n")
            if self.hiden!=None:
                report_file.write(self.hiden+'\n\n')
            else:
                report_file.write("Нет"+'\n\n')             
            report_file.write("Загруженные DLL:\n")
            if self.dlls:
                for file in self.dlls:
                    if file:
                        report_file.write(file+'\n')

            report_file.write("\nАргументы командной строки:\n")
            if self.cmd:
                report_file.write(self.cmd+"\n")         
            else:
                report_file.write("Не найдено\n\n")       
            

            report_file.write("\nВзаимодействие с файлами:\n")
            if self.check_func_file!=None:
                report_file.write(self.check_func_file+'\n\n')


            report_file.write("Найденные пути в дампе процесса:\n")
            if self.path_artifacts!=[]:
                for path_art in self.path_artifacts:
                    report_file.write(path_art+'\n')
            else:
                report_file.write("Не найдены\n\n")

            report_file.write("\nНайденные адреса сайтов в дампе процесса:\n")
            if self.domain_artifacts!=[]:
                for dom_art in self.domain_artifacts:
                    report_file.write(dom_art+'\n')
            else:
                report_file.write("Не найдены\n\n")
            
            report_file.write("\nНайденные IP в дампе процесса:\n")
            if self.hosts_artifacts!=[]:
                for host_art in self.hosts_artifacts:
                    report_file.write(host_art+'\n')
            else:
                report_file.write("Не найдены\n\n")

            report_file.write("\nСписок возможных сетевых взаимодействий\n")
            if self.domain_list!=[]:
                for item in self.domain_list:
                    report_file.write(json.dumps(item))
                    report_file.write("\n")
            else:
                report_file.write("Не найдены\n\n")
            
            report_file.write("\n\nВозможные иньекции кода\n")
            if self.malfind_date!=None:
                report_file.write(json.dumps(self.malfind_date))
                report_file.write("\n")
            else:
                report_file.write("Не обнаружены")

    
    
    
    
    
    def create_template(self):
        new_dict={}
        new_dlls=[]
        if self.dlls:
            for i in self.dlls:
                if i!=None:
                    new_dlls.append(i.split(os.sep)[-1])
       
        new_conn=[]
        if self.net_list:
            for ips in self.net_list:
                if ips['ForeignAddr']!="*":
                    new_conn.append(ips['ForeignAddr'])
        
        new_temp_files=[]
        new_files=[]
        if self.files_on_images:
            for file in self.files_on_images:
                new_temp_files.append(file['Name'])
            new_files=[]
            new_files = list(set(new_temp_files))

        new_domains=[]
        if self.domain_list:
            for dm in self.domain_list:
                if dm['Domain']!="Не найден":
                    new_domains.append(dm['Domain'])
        

        new_dict={
            "name":self.name.split('|')[0], \
            "file_action": "None" if self.check_func_file=="Не обнаружено" else "Yes", \
            "hide": "None" if not self.hiden else "Yes", \
            "dlls": new_dlls, \
            "cmd_line": "None" if not self.cmd else self.cmd, \
            "malfind": self.malfind_date if self.malfind_date else "None", \
            "connections": new_conn, \
            "files":new_files,\
            "domains": new_domains
        }

        self.db_dict=new_dict




           
            






