import volatility_func
from Process import Process
import utilities.utilities as utils
import ProcScan
from web_view import TestView
import flask
from FileImageWorker.FileWorker import FileFinder



app1 = flask.Flask(__name__)
app1.config['UPLOAD_FOLDER'] = "upload"

#new_scan = volatility_func.VolFunc("C:\\Users\\Konstantin\\diplom\\vulnefindproject_diplom\\volatility3-develop\\OtterCTF.vmem")

#new_scan1=ProcScan.ProcScan("E:\\diplom\\vulnefindproject_diplom\\volatility3-develop\\memory.dmp","image.vmdk")
#new_scan1.view_diff_dict()
#new_scan1.view_dll_graph()
#new_scan1.view_interval()
#scan = FileFinder("image.vmdk",None)
#print(scan.list_of_requests[1000])
#new_scan1.gen_report_for_all_proccesses()
flask_view = TestView()
flask_view.register(app1,route_base = '/')
app1.run(debug=True) 