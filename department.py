from fastapi import FastAPI, HTTPException, Query
from datetime import datetime
from pymongo import MongoClient, ReturnDocument
from bson import json_util
from enum import Enum
from typing import List, Optional

app = FastAPI()


class Status(str, Enum):
    Active = "Active"
    Inactive = "Inactive"


@app.on_event("startup")
async def startup_event():
    # Connect to MongoDB
    client = MongoClient('mongodb://localhost:27017/')
    db = client['department_db']
    app.collection = db['departments']
    app.sequence_collection = db['sequence']


def fetch_next_dept_id():
    sequence_document = app.sequence_collection.find_one_and_update(
        {"_id": "dept_id"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    sequence = sequence_document["seq"]
    return f"DPID{sequence:06}"


def create_uid(str_org, n):
    user_num = n + 1
    str1 = f'{user_num:06}'
    uid_str = f"U-{str_org}-{str1}"
    return uid_str


@app.post('/insert_department')
def create_department(organisation_id: int, department_name: str):
    # Check for duplicates
    existing_department = app.collection.find_one(
        {"organisation_id": organisation_id, "department_name": department_name})
    if existing_department:
        raise HTTPException(
            status_code=409, detail="Department already exists")

    # Automatically generate department_id
    department_id = fetch_next_dept_id()

    today = datetime.now()
    department = {
        "organisation_id": organisation_id,
        "department_id": department_id,
        "department_name": department_name,
        "creation_date": today,
        "update_date": today,
        "status": Status.Active  # Assuming "Active" is the default status
    }
    app.collection.insert_one(department)
    return {"message": "Department created successfully"}


@app.get('/get_departments')
def get_departments(organisation_id: Optional[int] = Query(None, description="Select organisation ID", alias="organisation_id")):
    if organisation_id is None or organisation_id == "ALL":
        departments = list(app.collection.find())
    else:
        departments = list(app.collection.find(
            {"organisation_id": organisation_id}))

    # Convert ObjectId to string for each document
    for department in departments:
        department['_id'] = str(department['_id'])

    # Get the minimum department_id
    min_department_id = min(int(department['department_id'][4:])
                            for department in departments if department['department_id'].startswith("DPID"))

    # Get list of unique organization IDs
    organization_ids = set(department['organisation_id']
                           for department in departments)

    # Convert list of dictionaries to JSON
    return {"departments": json_util.dumps(departments), "min_department_id": min_department_id, "organisation_ids": list(organization_ids)}


@app.put('/edit_department/{organisation_id}/{department_id}')
def edit_department(organisation_id: int, department_id: str, department_name: str):
    # Check if department exists
    department = app.collection.find_one(
        {"organisation_id": organisation_id, "department_id": department_id})
    if not department:
        raise HTTPException(status_code=404, detail="Department not found")

    # Convert ObjectId to string
    department['_id'] = str(department['_id'])

    # Save previous department details
    previous_department = department.copy()

    # Update department details
    today = datetime.now()
    result = app.collection.update_one(
        {"organisation_id": organisation_id, "department_id": department_id},
        {"$set": {"department_name": department_name, "update_date": today}}
    )
    if result.modified_count == 1:
        return {"message": "Department updated successfully", "previous_department": previous_department}
    else:
        return {"message": "Department not updated"}


@app.put('/update_department_status/{organisation_id}/{department_id}')
def update_department_status(organisation_id: int, department_id: str, status: Status):
    # Check if department exists
    department = app.collection.find_one(
        {"organisation_id": organisation_id, "department_id": department_id})
    if not department:
        raise HTTPException(status_code=404, detail="Department not found")

    # Convert ObjectId to string
    department['_id'] = str(department['_id'])

    # Save previous department details
    previous_department = department.copy()

    # Update department status
    today = datetime.now()
    result = app.collection.update_one(
        {"organisation_id": organisation_id, "department_id": department_id},
        # Use status.value to get the enum value
        {"$set": {"status": status.value, "update_date": today}}
    )
    if result.modified_count == 1:
        return {"message": f"Department status updated to {status}", "previous_department": previous_department}
    else:
        return {"message": "Department status not updated"}
