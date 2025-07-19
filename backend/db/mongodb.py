from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Get environment variables
MONGO_URI = os.getenv("MONGO_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME")

# Raise error if values are missing
if not MONGO_URI or not DATABASE_NAME:
    raise Exception("❌ MONGO_URI or DATABASE_NAME not set in .env")

# Create MongoDB client
client = AsyncIOMotorClient(MONGO_URI)
db = client[DATABASE_NAME]

# Collections
org_collection = db["organizations"]
emp_collection = db["employees"]
user_collection = db["users"]
