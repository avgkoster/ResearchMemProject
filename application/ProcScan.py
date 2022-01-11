import utilities.utilities as utils
import Process
import volatility_func
from FileImageWorker.FileWorker import FileFinder
from utilities.graphs import GraphWorker
from utilities.MBDWorker import MBDWorker
import os,sys

class ProcScan:

    List_Proccesses=[]
    db = None
    path = os.path.abspath(os.path.dirname(sys.argv[0]) )


    def __init__(self,path_dump:str,image:str,interval):
        self.interval=interval
        worker = MBDWorker('172.16.0.158')
        self.db=worker.get_from_db()
        new_scan = volatility_func.VolFunc(self.path+'\\'+path_dump)
        self.systime=self.scan_systime(new_scan.view_info())
        self.all_cmd=new_scan.view_cmdline()
        self.all_dlls= new_scan.view_dlllist()
        self.non_hided_proccesses=new_scan.view_pslist()
        self.all_proccesses=new_scan.view_psscan()
        self.list_mal=new_scan.view_malfind()
        self.net_list = new_scan.view_netscan()
        self.name_dump=path_dump.split('\\')[-1]
        self.userasit=new_scan.view_userassistview()
        self.create_list_proccesses()
        self.gen_proc_list_func()
        scan = FileFinder(image,self.List_Proccesses)
        graph = GraphWorker(self.List_Proccesses)
        self.create_json_dict(self.List_Proccesses)
        utils.diff_of_db(self.db,self.List_Proccesses)
        #print(self.view_interval())

    def create_list_proccesses(self):
        for i in self.all_proccesses:
            split_name = f"{i['ImageFileName']}|{i['CreateTime']}"
            self.List_Proccesses.append(Process.Process(split_name,i['PID'], i['CreateTime'], \
            i['ExitTime'],self.all_dlls,cmd=self.all_cmd,system_time=self.systime,interval=self.interval))
                
        for item in self.userasit:
            for item2 in item['__children']:
                check=0
                if '.exe' in item2['Name']:
                    name=item2['Name'].split('\\')[-1]
                    for item3 in self.List_Proccesses:
                        if item3.name.split('|')[0] in name:
                            check=1
                    if check!=1:        
                        split_name1 = f"{name}|{item2['Last Write Time']}"
                        self.List_Proccesses.append(Process.Process(split_name1,"UserAssistPotentialProc", item2['Last Write Time'], \
            None,self.all_dlls,path=item2['Name']))          

    def scan_systime(self,dic:dict):
        for i in dic:
            if i['Variable'] == 'SystemTime':
                return i['Value']


    def gen_proc_list_func(self):
        utils.check_proccesses_on_hide(self.non_hided_proccesses,self.List_Proccesses)
        utils.exports_dumps_process(self.name_dump,self.List_Proccesses)
        utils.check_proccesses_on_malfind(self.List_Proccesses,self.list_mal)
        utils.exports_strings_process(self.List_Proccesses)   
        utils.check_netscan(self.List_Proccesses,self.net_list)
        utils.find_artifacts_in_dump(self.List_Proccesses) 



    
    def create_json_dict(self,proclist:list):
        for proc in self.List_Proccesses:
            if proc.pid!="UserAssistPotentialProc":
                proc.create_template()


    
    def load_to_base(self,add_list:list):
        db_work=MBDWorker('172.16.0.158')
        for i in self.List_Proccesses:
            if str(i.pid) in add_list:
                print("OK")
                if i.db_dict:
                   db_work.insert_document(i.db_dict)



    def view_diff_dict(self):
        for proc in self.List_Proccesses:
            print(proc.name,proc.diff_dict)   
    
    def view_db_dict(self):
        for proc in self.List_Proccesses:
            print(proc.db_dict)

    def view_cmd(self):
        for proc in self.List_Proccesses:
            print(proc.pid,proc.cmd)        
    
    def view_procs(self):
        for proc in self.List_Proccesses:
            print(proc.pid,proc.name)

    def view_paths(self):
        for proc in self.List_Proccesses:
            print(proc.pid,proc.path)

    def view_dump_files(self):
        for proc in self.List_Proccesses:
            print(proc.pid,proc.dumpfile)     

    def view_domain_list(self):
        for proc in self.List_Proccesses:
            if proc.domain_list!=[]:
                print(proc.pid,proc.domain_list)   
    def view_check_func(self):
        for proc in self.List_Proccesses:
                print(proc.pid,proc.check_func_file) 

    def view_interval(self):
        for proc in self.List_Proccesses:
                print(proc.pid,proc.time_interval) 

    def gen_report_for_all_proccesses(self):
        for proc in self.List_Proccesses:
            proc.generate_text_report()

    def view_dll_graph(self):
        for proc in self.List_Proccesses:
            print(proc.name,proc.dll_graph)   

    def view_net_graph(self):
        for proc in self.List_Proccesses:
            print(proc.name,proc.net_graph)   