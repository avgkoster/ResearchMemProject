
from requests.api import request
from volatility3 import framework
from volatility3.framework import constants, contexts
import volatility3
from volatility3 import plugins
from volatility3.framework import automagic
from volatility3.framework.interfaces.configuration import path_join
from volatility3.plugins.windows.statistics import Statistics
from volatility3.plugins.windows.pslist import PsList
from volatility3.plugins.windows.dlllist import DllList
from volatility3.plugins.windows.psscan import PsScan
from volatility3.framework.symbols.windows import WindowsKernelIntermedSymbols
import os
import urllib.request
from volatility3.cli.text_renderer import JsonRenderer
from utilities.render_json import JsonRenderer_mod
from volatility3.cli.volshell.generic import NullFileHandler
from volatility3.framework.interfaces.configuration import path_join
from volatility3.plugins.windows.malfind import Malfind
from volatility3.plugins.windows.netscan import NetScan
from volatility3.plugins.windows.cmdline import CmdLine
from volatility3.plugins.windows.registry.userassist import UserAssist
from volatility3.plugins.windows.info import Info

class VolFunc:

    def __init__(self,file_name:str):
        framework.require_interface_version(1,0,2)
        self.ctx = contexts.Context()
        self.file_name_mem = os.path.abspath(file_name)
        self.single_location = "file:"+ urllib.request.pathname2url(self.file_name_mem)
        self.ctx.config['automagic.LayerStacker.single_location'] = self.single_location
        self.failures = framework.import_files(plugins, True)
        


    def view_pslist(self):
        available_automagic=automagic.available(self.ctx)
        automagics = automagic.choose_automagic(available_automagic,volatility3.plugins.windows.pslist.PsList)
        constructed = volatility3.framework.plugins.construct_plugin(self.ctx,automagics,volatility3.plugins.windows.pslist.PsList,base_config_path="Library_Plugins",progress_callback=None,open_method=None)
        treegrid=constructed.run()
        test = JsonRenderer_mod()
        test.render(treegrid)
        return test.output_dict

    def view_dlllist(self):
        available_automagic=automagic.available(self.ctx)
        automagics = automagic.choose_automagic(available_automagic,volatility3.plugins.windows.dlllist.DllList)
        constructed = volatility3.framework.plugins.construct_plugin(self.ctx,automagics,volatility3.plugins.windows.dlllist.DllList,base_config_path="Library_Plugins",progress_callback=None,open_method=None)
        treegrid=constructed.run()
        test = JsonRenderer_mod()
        test.render(treegrid)
        return test.output_dict
    
    def view_psscan(self):
        available_automagic=automagic.available(self.ctx)
        automagics = automagic.choose_automagic(available_automagic,volatility3.plugins.windows.psscan.PsScan)
        constructed = volatility3.framework.plugins.construct_plugin(self.ctx,automagics,volatility3.plugins.windows.psscan.PsScan,base_config_path="Library_Plugins",progress_callback=None,open_method=None)
        treegrid=constructed.run()
        test = JsonRenderer_mod()
        test.render(treegrid)
        return test.output_dict

    def view_malfind(self):
        available_automagic=automagic.available(self.ctx)
        automagics = automagic.choose_automagic(available_automagic,volatility3.plugins.windows.malfind.Malfind)
        constructed = volatility3.framework.plugins.construct_plugin(self.ctx,automagics,volatility3.plugins.windows.malfind.Malfind,base_config_path="Library_Plugins",progress_callback=None,open_method=None)
        treegrid=constructed.run()
        test = JsonRenderer_mod()
        test.render(treegrid)
        return test.output_dict


    def view_netscan(self):
        available_automagic=automagic.available(self.ctx)
        automagics = automagic.choose_automagic(available_automagic,volatility3.plugins.windows.netscan.NetScan)
        constructed = volatility3.framework.plugins.construct_plugin(self.ctx,automagics,volatility3.plugins.windows.netscan.NetScan,base_config_path="Library_Plugins",progress_callback=None,open_method=None)
        treegrid=constructed.run()
        test = JsonRenderer_mod()
        test.render(treegrid)
        return test.output_dict

    def view_userassistview(self):
        available_automagic=automagic.available(self.ctx)
        automagics = automagic.choose_automagic(available_automagic,volatility3.plugins.windows.registry.userassist.UserAssist)
        constructed = volatility3.framework.plugins.construct_plugin(self.ctx,automagics,volatility3.plugins.windows.registry.userassist.UserAssist,base_config_path="Library_Plugins",progress_callback=None,open_method=None)
        treegrid=constructed.run()
        test = JsonRenderer_mod()
        test.render(treegrid)
        return test.output_dict


    def view_cmdline(self):
        available_automagic=automagic.available(self.ctx)
        automagics = automagic.choose_automagic(available_automagic,volatility3.plugins.windows.cmdline.CmdLine)
        constructed = volatility3.framework.plugins.construct_plugin(self.ctx,automagics,volatility3.plugins.windows.cmdline.CmdLine,base_config_path="Library_Plugins",progress_callback=None,open_method=None)
        treegrid=constructed.run()
        test = JsonRenderer_mod()
        test.render(treegrid)
        return test.output_dict

    def view_info(self):
        available_automagic=automagic.available(self.ctx)
        automagics = automagic.choose_automagic(available_automagic,volatility3.plugins.windows.info.Info)
        constructed = volatility3.framework.plugins.construct_plugin(self.ctx,automagics,volatility3.plugins.windows.info.Info,base_config_path="Library_Plugins",progress_callback=None,open_method=None)
        treegrid=constructed.run()
        test = JsonRenderer_mod()
        test.render(treegrid)
        return test.output_dict

