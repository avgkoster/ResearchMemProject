import pymongo

class MBDWorker:

    def __init__(self,db_addr:str) -> None:
        self.client = pymongo.MongoClient(db_addr,27017)
        self.db = self.client['volatility']
        self.series_collection = self.db['proccesses']

    def insert_document(self, data):
        """ Function to insert a document into a collection and
            return the document's id.
        """
        data1=self.series_collection.insert_one(data)

    def get_from_db(self):
        prc_list=[]
        cursor = self.series_collection.find({})
        for doc in cursor:
            prc_list.append(doc)
        
        return prc_list

    def view_db(self):
        cursor = self.series_collection.find({})
        for document in cursor:
            print(document)

