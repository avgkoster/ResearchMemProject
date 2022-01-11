import subprocess
import os,sys
import sqlite3

class FileWorker:

    path = os.path.abspath(os.path.dirname(sys.argv[0]) )

    def __init__(self,image_file:str):
        self.class_image_file=image_file
        commands=[]
        commands.append(f"{self.path}\\FileImageWorker\\sleuthkit\\bin\\tsk_loaddb.exe")
        commands.append("-k")
        commands.append(f"{self.path}\\upload\\{self.class_image_file}")
        self.create_file_db(commands)
        

    def create_file_db(self,commands:list):
        if not os.path.exists(f"{self.path}\\upload\\{self.class_image_file}.db"):
            load_db=subprocess.Popen(commands)
            status=load_db.wait()
            if status==0:
                print("Успешно")
                self.path_to_db=f"{self.path}\\upload\\{self.class_image_file}.db"
            else:
                print("Не успешно")
            


class FileFinder:

    def __init__(self,image_file,list_proc):
        self.imagedb=FileWorker(image_file)
        self.list_proc=list_proc
        self.connect_db()
        self.parse_files()
        self.close()

    def connect_db(self):
        if os.path.exists(f"{self.imagedb.path}\\upload\\{self.imagedb.class_image_file}.db"):
            try:
                self.sqlite_conn=sqlite3.connect(f"{self.imagedb.path}\\upload\\{self.imagedb.class_image_file}.db")
                self.sqlite_conn.row_factory=sqlite3.Row
                print("База загружена")
            except sqlite3.Error as error:
                print("Ошибка подключения")
        else:
            print("Отсутствует база")

    def parse_files(self):
        self.list_of_requests=[]
        len=0
        cur = self.sqlite_conn.cursor()
        for proc in self.list_proc:
            interval=[]
            proc.files_on_images=[]
            interval=proc.time_interval
            if interval[0]!=None and interval[1]!=None and proc.pid!="UserAssistPotentialProc":
                cur.execute(f"SELECT name,parent_path,ctime,crtime,atime,mtime \
                    FROM tsk_files WHERE name!='.' AND name!='..' AND name NOT LIKE '%slack%' AND name  NOT LIKE '%mui%' \
                    AND name!='' AND (ctime>={interval[0]} AND ctime <={interval[1]});")
                for row in cur.fetchall():
                    new_dict1=dict(row)
                    proc.files_on_images.append({'Name':new_dict1['name'],'Full Path':new_dict1['parent_path']+ \
                    new_dict1["name"],'Time':new_dict1['ctime'],'action':'Изменение метадаты файла'})
            ##################################
                cur.execute(f"SELECT name,parent_path,ctime,crtime,atime,mtime \
             FROM tsk_files WHERE name!='.' AND name!='..' AND name NOT LIKE '%slack%' AND name  NOT LIKE '%mui%' \
                 AND name!='' AND (crtime>={interval[0]} AND crtime <={interval[1]});")
                for row1 in cur.fetchall():
                    new_dict2=dict(row1)
                    proc.files_on_images.append({'Name':new_dict2['name'],'Full Path':new_dict2['parent_path']+ \
                    new_dict2["name"],'Time':new_dict2['crtime'],'action':'Создание файла'})
            ####################################
                cur.execute(f"SELECT name,parent_path,ctime,crtime,atime,mtime \
             FROM tsk_files WHERE name!='.' AND name!='..' AND name NOT LIKE '%slack%' AND name  NOT LIKE '%mui%' \
                 AND name!='' AND (mtime>={interval[0]} AND mtime <={interval[1]});")
                for row2 in cur.fetchall():
                    new_dict3=dict(row2)
                    proc.files_on_images.append({'Name':new_dict3['name'],'Full Path':new_dict3['parent_path']+ \
                    new_dict3["name"],'Time':new_dict3['mtime'],'action':'Модификация файла'})
            #########################################
                cur.execute(f"SELECT name,parent_path,ctime,crtime,atime,mtime  \
             FROM tsk_files WHERE name!='.' AND name!='..' AND name NOT LIKE '%slack%' AND name  NOT LIKE '%mui%' \
                 AND name!='' AND (atime>={interval[0]} AND atime <={interval[1]});")
                for row3 in cur.fetchall():
                    new_dict4=dict(row3)
                    proc.files_on_images.append({'Name':new_dict4['name'],'Full Path':new_dict4['parent_path']+ \
                    new_dict4["name"],'Time':new_dict4['atime'],'action':'Доступ к файлу'})
    def close(self):
        self.sqlite_conn.close()        



