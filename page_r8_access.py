from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pymongo import MongoClient

app = FastAPI()

# MongoDB connection
client = MongoClient(
    "mongodb+srv://somnath:somnath@cluster0.izhugny.mongodb.net/")
db = client["LocalDB"]
page_rights_access_collection = db["page_rights_access"]

# Pydantic models


class PageRightsAccess(BaseModel):
    admin_id: str
    org_id: str
    user_id: str
    admin_dashboard: list
    admin_master: list
    dept_mgmt: list
    area_mgmt: dict
    industry_sector_mgmt: list
    roles_mgmt: list
    skill_mgmt: list
    role_id: list
    user_mgmt: list
    list_user: list
    page_right: list
    register_org: dict
    candidate_mgmt: list
    admin_subscriber: dict

# Create entry in page_rights_access collection


@app.post("/create_page_rights_access/")
async def create_page_rights_access(page_rights_access: PageRightsAccess):
    # Check if user already exists in the collection
    if page_rights_access_collection.find_one({"user_id": page_rights_access.user_id}):
        raise HTTPException(status_code=400, detail="User already exists")

    # Insert new page rights access document
    page_rights_access_dict = page_rights_access.dict()
    page_rights_access_collection.insert_one(page_rights_access_dict)
    return {"message": "Page rights access created successfully"}

# Update page rights access


@app.patch("/update_page_rights_access/{user_id}")
async def update_page_rights_access(user_id: str, page_rights_access: PageRightsAccess):
    # Check if user exists
    existing_page_rights_access = page_rights_access_collection.find_one({
                                                                         "user_id": user_id})
    if not existing_page_rights_access:
        raise HTTPException(status_code=404, detail="User not found")

    # Update existing document
    page_rights_access_dict = page_rights_access.dict()
    page_rights_access_collection.update_one(
        {"user_id": user_id}, {"$set": page_rights_access_dict})
    return {"message": "Page rights access updated successfully"}
