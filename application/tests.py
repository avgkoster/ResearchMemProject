import re
import socket
import calendar
import datetime
from deepdiff import DeepDiff  # For Deep Difference of 2 objects
from deepdiff import grep, DeepSearch  # For finding if item exists in an object
from deepdiff import DeepHash 
from jsondiff import diff
import validators
import ipaddress
import pymongo
#Поиск доменов
# result = re.search(r'https?://[\S][^>]+', 'i fuck the https://git.pampei.ru:8080')
# print(result[0])
# #Поиск адресов с портами
# result1 = re.search(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d{1,5}\b', '192.168.0.1:80')
# print(result1)
# #Поиск адресов без портов
# result2 = re.search(r'\d{1,3}(?:\.\d{1,3}){3}$', '192.168.0.1')
# print(result2)

# # Поиск файлов и путей
# result3 = re.search(r'[a-zA-Z]:\\((?:[a-zA-Z0-9() ]*\\)*).*', r'C:\Users\username\Documents\Files\aa.xx')
# print(result3)


# find_domain = socket.gethostbyaddr('5.165.27.92')
# print(find_domain[0])


# dt = datetime.datetime.today()  
# dt1 = datetime.datetime.timetuple(dt)
# cal = calendar.timegm(dt1)
# print(type(cal))


# client = pymongo.MongoClient('172.16.0.43',27017)

# db = client['volatility']

# series_collection = db['proccesses']

# #print(series_collection)
# def insert_document(collection, data):
#     """ Function to insert a document into a collection and
#     return the document's id.
#     """
#     return collection.insert_one(data).inserted_id

# cursor = series_collection.find({})

# for document in cursor:
#     print(document)


# new_show = {
#     "name": "FRIENDS",
#     "year": 1994
# }
val=0
db = {'name':'fuck','val':34}

if db['name']=='fuck':
    val=val+1
if db['val']==34:
    val=val+1

print(val)
# print(insert_document(series_collection, new_show))

#print(ipaddress.IPv4Address("1.0.0.0"))