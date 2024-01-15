from pymongo import MongoClient
from django.conf import settings

def get_mongo_client():
    return MongoClient(settings.MONGODB_URI)

def get_mongo_database():
    client = get_mongo_client()
    return client.get_default_database()
