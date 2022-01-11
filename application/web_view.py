from flask_classful import FlaskView,route
from flask import render_template, request, make_response, jsonify,url_for,redirect
import os

from werkzeug.utils import secure_filename
import ProcScan
from utilities.MBDWorker import MBDWorker
import os,glob,sys

class TestView(FlaskView):
    vmem_file=None
    vmdk_file=None
    list_proc=None
    def __init__(self,list_proc=None) -> None:
        super().__init__()
        self.procs=list_proc

    
    @route('/db', methods=["GET", "POST"])
    def db(self):
        worker = MBDWorker('172.16.0.158')
        db_series=worker.get_from_db()
        return render_template("db.html",proc_dict=db_series)

    intrv=int(0)
    check=0


    
    @route('/test', methods=["GET", "POST"])
    def test(self):
        print(self.check)
        self.vmem_file="test"
        return redirect("/index")     


    @route('/', methods=["GET", "POST"])
    @route('/index', methods=["GET", "POST"])
    def index(self):
        self.vmdk_file="image.vmdk"
        self.vmem_file="ram.vmem" 
        ram_status="None"
        image_status="None"
        css_load=url_for('static', filename='style.css', v=1)   
        if request.method == "POST":
            if request.form.get("next")=="Далее":
                return redirect("/scan")
            elif request.form.get("reset")=="Сброс":
                print(request.form.get("reset"))
                filelist = glob.glob(os.path.join("upload\\", "*"))
                for f in filelist:
                    os.remove(f)
                self.check=0
                return redirect("/index")
            else:   
                file = request.files["file"]
                file1 = request.files["file1"]
                self.vmem_file=secure_filename(request.files["file"].filename)
                self.vmdk_file=secure_filename(request.files["file1"].filename)
                print("File uploaded")
                print(file)
                if file and file1:
                    if file.filename.split('.')[1]=='vmem' and file1.filename.split('.')[1]=='vmdk':
                        self.check=1
                        ram_status="Success"
                        image_status="Success"
                        file.save("upload\\"+self.vmem_file)
                        file1.save("upload\\"+self.vmdk_file)
                        return render_template("upload.html",ram=ram_status,image=image_status,check=self.check)
                else:
                    return redirect("/error")
        if self.vmdk_file and self.vmem_file:
            ram_status="Success"
            image_status="Success"     
            self.check=1       
        
        return render_template("upload.html",ram=ram_status,image=image_status,check=self.check)

    @route("/error", methods=["GET", "POST"])
    def error(self):
        if request.method=="POST":
            return redirect("/index")
        return render_template("error.html")


    @route("/success", methods=["GET", "POST"])
    def success(self):
        if request.method=="POST":
            self.list_proc=None
            self.vmdk_file="image.vmdk"
            self.vmem_file="ram.vmem" 
            return redirect("/index")
        return render_template("success.html")


        
    @route("/scan",methods=["GET","POST"])
    def scan(self):
        status=1
        self.vmdk_file="image.vmdk"
        self.vmem_file="ram.vmem" 
        if request.method=="POST":
            status=0
            self.intrv=int(request.form.get("intrv"))
            print(int(request.form.get("intrv")))
            if request.form.getlist('proc')!=[]:
                self.to_base = request.form.getlist('proc')
                print(self.to_base)
                self.new_scan1.load_to_base(self.to_base)
                return redirect("/success")
            if self.list_proc==None:
                self.new_scan1=ProcScan.ProcScan("upload\\"+self.vmem_file,self.vmdk_file,self.intrv)
                self.list_proc=self.new_scan1.List_Proccesses
            return render_template("scan.html",list_proc=self.list_proc)
        elif self.list_proc!=None:
            return render_template("scan.html",list_proc=self.list_proc)               
        return render_template("scan.html",status=status)





    @route('/diffrentname')
    def bsicname(self):
    # customized route
    # http://localhost:5000/diffrentname
        return "<h1>This is my custom route</h1>"

