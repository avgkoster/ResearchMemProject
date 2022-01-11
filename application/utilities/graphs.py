from bokeh.core.property.numeric import Size
from bokeh.models import ColumnDataSource
from bokeh.plotting import figure, output_file, show
from datetime import datetime,timedelta
from bokeh.models import HoverTool
from bokeh.models import DatetimeTickFormatter, NumeralTickFormatter
import time
from bokeh.resources import INLINE
from bokeh.embed import components
from dateutil import parser
#print(parser.parse("2018-08-04 19:27:25")) 
import pandas as pd
import utilities.utilities as utils

class GraphWorker:


    def __init__(self,list_proc:list):

        self.net_list=[]
        self.dll_list=[]
        self.files_list=[]
        self.run_proc_list=[]

        self.list_proc=list_proc
        self.create_new_dicts()
        self.create_model_graph()

    def create_new_dicts(self):
        #dll
        for proc in self.list_proc:
            net_graph=[]
            list_graph=[]
            files_graph=[]
            for elem in proc.time_dlls:
                    if elem['time']!=None:
                        ts = utils.convert_time_to_seconds(elem['time'])
                        date4 =datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        #time_temp=datetime.strptime(elem['time'],'%Y-%m-%dT%H:%M:%S')
                        #time=date4.strftime("%Y-%m-%d %H:%M:%S")
                    elif proc.str_time!=None:
                        ts1 = utils.convert_time_to_seconds(proc.str_time)
                        date4 =datetime.utcfromtimestamp(ts1).strftime('%Y-%m-%d %H:%M:%S')
                        #time_temp=datetime.strptime(proc.str_time,'%Y-%m-%dT%H:%M:%S')
                        #time=date4.strftime("%Y-%m-%d %H:%M:%S")     
                    else:
                        ts2 = utils.convert_time_to_seconds(proc.systime)
                        date4 =datetime.utcfromtimestamp(ts2).strftime('%Y-%m-%d %H:%M:%S')                       
                        #time_temp=datetime.strptime(proc.systime,'%Y-%m-%dT%H:%M:%S')
                        #time=date4.strftime("%Y-%m-%d %H:%M:%S")                                             
                    list_graph.append({'type':'1','dt':datetime.strptime(date4,'%Y-%m-%d %H:%M:%S'), \
                    'data':elem['name'], \
                    'inc':"Загрузка DLL"})
            for elem2 in proc.net_list:
                if elem2['Created']:
                    ts3 = utils.convert_time_to_seconds(elem2['Created'])
                    date4 =datetime.utcfromtimestamp(ts3).strftime('%Y-%m-%d %H:%M:%S')    
                    #time_temp2=datetime.strptime(elem2['Created'],'%Y-%m-%dT%H:%M:%S')
                    #time2=time_temp2.strftime("%Y-%m-%d %H:%M:%S")  
                    net_graph.append({'type':'2','dt':datetime.strptime(date4,'%Y-%m-%d %H:%M:%S'), \
                    'data':elem2['ForeignAddr'], \
                    'inc':"Сетевое соединение"})
            if proc.files_on_images:
                for elem3 in proc.files_on_images:
                    date3 =datetime.utcfromtimestamp(elem3['Time']).strftime('%Y-%m-%d %H:%M:%S')
                    files_graph.append({'type':'3','dt':datetime.strptime(date3,'%Y-%m-%d %H:%M:%S'), \
                    'data':elem3['Full Path'], \
                    'inc':elem3['action']})

            proc.files_graph=files_graph
            proc.net_graph=net_graph
            proc.dll_graph=list_graph

        print(self.dll_list)
        #dll


    def create_model_graph(self):
        for proc1 in self.list_proc:
            if proc1.pid!="UserAssistPotentialProc":
                p = figure(title=f"Временные ряды {proc1.name.split('|')[0]}",y_range=(0, 4),x_axis_type="datetime",sizing_mode="stretch_width",height=350)
                if proc1.net_graph:
                    df1 = pd.DataFrame(data=proc1.net_graph)
                    df1['date_time'] = pd.to_datetime(df1['dt'], unit='us')
                    p.circle(x='date_time',y='type',source=df1,size=15,legend_label="Сетевые соединения")
                    p.line(x='date_time',y='type',source=df1)
                if proc1.dll_graph:
                    df2 = pd.DataFrame(data=proc1.dll_graph)
                    df2['date_time'] = pd.to_datetime(df2['dt'], unit='us')
                    p.circle(x='date_time',y='type',source=df2,size=15,color="red",legend_label="Загруженные DLL")
                    p.line(x='date_time',y='type',source=df2,line_color="red")
                if proc1.files_graph:
                    df3 = pd.DataFrame(data=proc1.files_graph)
                    df3['date_time'] = pd.to_datetime(df3['dt'], unit='us')
                    p.circle(x='date_time',y='type',source=df3,size=15,color="green",legend_label="Найденные файлы")
                    p.line(x='date_time',y='type',source=df3,line_color="green")


                hover = HoverTool(tooltips=[('Тип', '@inc'),('Имя', '@data'),('Время действия', '@date_time{"%Y-%m-%d %H:%M:%S"}')],formatters={'@date_time': 'datetime'})
                p.add_tools(hover)
                p.legend.location = "top_left"
                p.legend.label_text_font_size="15pt"
                p.xaxis[0].formatter = DatetimeTickFormatter(seconds = ["%Y-%m-%d %H:%M:%S"],minsec = ["%Y-%m-%d %H:%M:%S"],minutes = ["%Y-%m-%d %H:%M:%S"],hourmin = ["%Y-%m-%d %H:%M:%S"],hours=["%Y-%m-%d %H:%M:%S"],days=["%Y-%m-%d %H:%M:%S"],months=["%Y-%m-%d %H:%M:%S"],years=["%Y-%m-%d %H:%M:%S"])
                script, div = components(p)
                proc1.global_graph=[script,div,INLINE.render_js(),INLINE.render_css()]
                output_file("E:\\graphs\\"+str(proc1.pid)+"_graph.html")
            #show(p)
