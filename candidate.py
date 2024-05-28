from fastapi import FastAPI, HTTPException, Depends
from pymongo import MongoClient
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from bson.objectid import ObjectId
from datetime import datetime
import random

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["candidate_db"]
collection = db["candidates"]

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# FastAPI app
app = FastAPI()


class Candidate(BaseModel):
    full_name: str
    phone_number: str
    email: EmailStr
    password: str


class CandidateInDB(BaseModel):
    candidate_id: str
    full_name: str
    phone_number: str
    email: EmailStr
    hashed_password: str
    is_email_verified: bool


# Function to verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# Function to generate OTP
def generate_otp():
    return str(random.randint(100000, 999999))


# Function to get candidate from database
def get_candidate(email: str):
    candidate_data = collection.find_one({"email": email})
    if candidate_data:
        return CandidateInDB(**candidate_data)


# Register endpoint
@app.post("/register/")
async def register(candidate: Candidate):
    candidate_data = candidate.dict()
    if collection.find_one({"email": candidate.email}):
        raise HTTPException(
            status_code=400, detail="Email already registered")
    # Automatically generate candidate_id
    candidate_id = ObjectId()
    hashed_password = pwd_context.hash(candidate.password)
    otp = generate_otp()
    candidate_data.update({"candidate_id": str(candidate_id),
                           "hashed_password": hashed_password,
                           "is_email_verified": False,
                           "otp": otp})
    collection.insert_one(candidate_data)
    # Here you can send the OTP to the candidate's email for verification
    return {"message": "Candidate registered successfully. Check your email for OTP."}


# Login endpoint
@app.post("/login/")
async def login(email: EmailStr, password: str):
    candidate_data = get_candidate(email)
    if not candidate_data:
        raise HTTPException(status_code=401, detail="Invalid email")
    if not verify_password(password, candidate_data.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid password")
    if not candidate_data.is_email_verified:
        raise HTTPException(status_code=401, detail="Email not verified")
    return {"message": "Login successful"}
