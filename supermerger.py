from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from pymongo import MongoClient, ReturnDocument
from datetime import datetime, timedelta
import os
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
from enum import Enum
import string
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
# from my_module import Status
from fastapi import APIRouter
from fastapi import Query
from bson import json_util
from typing import List


app = FastAPI()

# Add CORSMiddleware to the application instance
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # List of allowed origins
    # Allows credentials (such as cookies, authorization headers, etc.) to be sent in cross-origin requests
    allow_credentials=True,
    # Allows all methods (such as GET, POST, DELETE, etc.)
    allow_methods=["*"],
    allow_headers=["*"],  # Allows all headers
    expose_headers=["*"]
)

# Load environment variables
load_dotenv()

EMAIL_ADDRESS = "snipe.upl@gmail.com"
EMAIL_PASSWORD = "ljzz hsqx qvwc fbdr"
MONGO_DETAILS = "mongodb+srv://somnath:somnath@cluster0.izhugny.mongodb.net/"
# mongodb+srv://shreyasraohmohite:Shreyas111@aicodedisha.wqjv1yv.mongodb.net/?retryWrites=true&w=majority
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# client = MongoClient(MONGO_DETAILS)

client = MongoClient(MONGO_DETAILS)
db = client.super_user_Login_Register
users_collection = db.super_user_Login_Register_Auth


db = client.Login_Register
users_collection = db.Login_Register_Auth

# client = MongoClient(MONGO_DETAILS)
database = client.Admin_Module
mycol = database.city_management

db1 = client.Role_Management
# mycol = db1.role
# org_ids_collection = db1.role_sequence

mycol1 = db1.user
user_sequence_collection = db1.user_sequence

mycol2 = db1.department
dept_sequence_collection = db1.dept_sequence

mycol3 = db1.Job_Desc
# ---------------------------------------------------------------------------------------------------------------------------------------


# Add CORSMiddleware to the application instance
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # List of allowed origins
    # Allows credentials (such as cookies, authorization headers, etc.) to be sent in cross-origin requests
    allow_credentials=True,
    # Allows all methods (such as GET, POST, DELETE, etc.)
    allow_methods=["*"],
    allow_headers=["*"],  # Allows all headers
    expose_headers=["*"]
)

# Load environment variables
load_dotenv()

# EMAIL_ADDRESS="snipe.upl@gmail.com"
# EMAIL_PASSWORD="ljzz hsqx qvwc fbdr"
# MONGO_DETAILS="mongodb+srv://somnath:somnath@cluster0.izhugny.mongodb.net/"
# SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

client = MongoClient(MONGO_DETAILS)
db = client.super_user_Login_Register
users_collection = db.super_user_Login_Register_Auth

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class Role(str, Enum):
    organization = "Organization"
    student = "Student"


class UserSchema(BaseModel):
    email: EmailStr
    role: Role  # Use the Role enum here
    name: str
    mobile_number: str
    password: str
    confirm_password: str
    # organization_id: Optional[str] = None  # New field for organization ID


class OTPVerificationSchema(BaseModel):
    email: EmailStr
    otp: int


class Token(BaseModel):
    access_token: str
    token_type: str
    organization_id: Optional[str] = None
    name: str
    role: Role
    email: EmailStr


class TokenData(BaseModel):
    email: Optional[str] = None


def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(email: str, password: str):
    user = users_collection.find_one({"email": email})
    if not user:
        return False
    if not verify_password(password, user['password']):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def send_email_otp(email: str, otp: int):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'Your OTP'

    body = f'Your OTP is: {otp}'
    message.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()


def save_user(user_data: UserSchema, hashed_password: str, otp: int):
    user_dict = user_data.dict()
    user_dict.pop('confirm_password')  # Remove confirm_password before saving
    user_dict['password'] = hashed_password
    user_dict['otp'] = otp
    user_dict['otp_expiry'] = datetime.utcnow(
    ) + timedelta(minutes=10)  # OTP expires in 10 minutes
    users_collection.insert_one(user_dict)


def generate_unique_organization_id(length=10):
    characters = string.ascii_uppercase + string.digits
    while True:
        organization_id = ''.join(random.choice(characters)
                                  for _ in range(length))
        if not users_collection.find_one({"organization_id": organization_id}):
            return organization_id


def send_password_reset_confirmation_email(email: str, name: str):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'Password Reset Confirmation'

    body = f'Hi {name},\n\nYour password has been successfully reset. If you did not initiate this change, please contact our support immediately.\n\nBest Regards,\nAI- Disha'
    message.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()


def send_welcome_email(email: str, name: str):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'Welcome to Our AI - Disha!'

    body = f'Hi {name},\n\nWelcome to AI- Disha!\nCongratulations you have Registered Successfully!!! \nWe are excited to have you on board.\n\nWe are glad you have registered to our platform. \nVisit: www.aidisha.com \n\nThanks & Regards,\nAI - Disha'
    message.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()


def get_client_ip(request: Request):
    client_host = request.client.host
    return client_host


def get_client_ip(request: Request):
    if "X-Forwarded-For" in request.headers:
        # In case there are multiple proxies, take the first one.
        return request.headers["X-Forwarded-For"].split(",")[0]
    return request.client.host


def send_new_device_login_email(email: str, ip: str, name: str):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'New Device Login Detected'

    body = f"""Hi {name},
    
A new login to your account was detected from a device using IP address {ip}.
If this was you, you can safely ignore this email. \nIf you do not recognize this login, we strongly recommend that you change your password immediately as your account may be compromised.

Best Regards,
AI- Disha"""
    message.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()


@app.post("/super-user-Register/")
async def send_otp(user_data: UserSchema):
    if user_data.password != user_data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")

    # Check if the email is already registered
    if users_collection.find_one({"email": user_data.email}):
        raise HTTPException(
            status_code=400, detail="Email already registered.")

    hashed_password = get_password_hash(user_data.password)
    otp = random.randint(100000, 999999)
    save_user(user_data, hashed_password, otp)
    send_email_otp(user_data.email, otp)

    return {"message": "OTP sent to the email. Please verify to complete registration."}


@app.post("/super-user-Register-Verify-OTP/")
async def verify_otp(otp_data: OTPVerificationSchema):
    user = users_collection.find_one({"email": otp_data.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    current_time = datetime.utcnow()
    if user.get('otp') == otp_data.otp and current_time < user.get('otp_expiry'):
        update_data = {"is_verified": True}
        if user.get('role') == Role.organization:
            organization_id = generate_unique_organization_id()
            update_data["organization_id"] = organization_id
        users_collection.update_one(
            {"email": otp_data.email}, {"$set": update_data})

        # Send welcome email
        send_welcome_email(otp_data.email, user['name'])

        return {"message": "OTP verified successfully. Registration complete."}
    else:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")


@app.post("/super-user-Login", response_model=Token)
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    email = form_data.username  # Treat the 'username' field as the user's email
    password = form_data.password

    user = authenticate_user(email, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Continue with your existing logic...

    # Example function to get client IP - implement this based on your requirements
    client_ip = get_client_ip(request)

    # Check if IP is new
    if client_ip not in user.get('known_ips', []):
        # If new, update known IPs and send email
        users_collection.update_one({"email": user['email']}, {
                                    "$addToSet": {"known_ips": client_ip}})
        send_new_device_login_email(user['email'], client_ip, user['name'])

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['email']}, expires_delta=access_token_expires
    )

    # Extract additional information from the user object
    organization_id = user.get('organization_id')
    name = user.get('name')
    role = user.get('role')
    email = user['email']

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "organization_id": organization_id,
        "name": name,
        "role": role,
        "email": email
    }


@app.post("/super-user-Forget-Password-Email/")
async def password_reset_send_otp(email: EmailStr):
    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="Email not found.")

    # Generate and save OTP
    otp = random.randint(100000, 999999)
    otp_expiry = datetime.utcnow() + timedelta(minutes=10)  # OTP expires in 10 minutes
    users_collection.update_one(
        {"email": email}, {"$set": {"reset_otp": otp, "reset_otp_expiry": otp_expiry}})

    # Send OTP to user's email
    send_email_otp(email, otp)

    return {"message": "OTP sent to the email. Please verify to proceed with password reset."}


@app.post("/super-user-Forget-Password/Verify-OTP/")
async def password_reset_verify_otp(otp_data: OTPVerificationSchema):
    user = users_collection.find_one({"email": otp_data.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    current_time = datetime.utcnow()
    if user.get('reset_otp') == otp_data.otp and current_time < user.get('reset_otp_expiry'):
        # Optionally, you could mark the OTP as used here to prevent reuse
        return {"message": "OTP verified successfully. You may now reset your password."}
    else:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")


@app.post("/super-user-Password-Reset/")
async def password_reset(otp_data: OTPVerificationSchema, new_password: str, confirm_password: str):
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")

    user = users_collection.find_one({"email": otp_data.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    current_time = datetime.utcnow()
    if user.get('reset_otp') == otp_data.otp and current_time < user.get('reset_otp_expiry'):
        hashed_password = get_password_hash(new_password)
        users_collection.update_one({"email": otp_data.email}, {
                                    "$set": {"password": hashed_password}})
        # Optionally, clear the OTP fields here to prevent reuse

        # Send password reset confirmation email
        send_password_reset_confirmation_email(otp_data.email, user['name'])

        return {"message": "Password reset successfully."}
    else:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")
-------------------------superuser/admin/sequence/skill------------------------------


class Status(str, Enum):
    active = "Active"
    inactive = "Inactive"


class DepartmentStatusUpdate(BaseModel):
    status: Status


class SectorStatusUpdate(BaseModel):
    status: Status


class SkillStatusUpdate(BaseModel):
    status: Status

# MongoDB connection details
# MONGO_DETAILS = "mongodb+srv://somnath:somnath@cluster0.izhugny.mongodb.net/"
# client = MongoClient(MONGO_DETAILS)
# database = client.Admin_Module
# mycol = database.city_management

# app = FastAPI()


# Department
department_collection = database.Dept_SuperUser
sequence_department_collection = database.Dept_Sequence_SuperUser


class Department(BaseModel):
    admin_id: str
    dept_name: str
    creation_date: datetime = Field(default_factory=datetime.utcnow)
    status: str = "Active"


class DepartmentInDB(Department):
    dept_id: str
    updated_date: datetime = None


class DepartmentUpdate(BaseModel):
    dept_name: str
    updated_date: datetime = Field(default_factory=datetime.utcnow)


def fetch_next_dept_id():
    sequence_document = sequence_department_collection.find_one_and_update(
        {"_id": "dept_id"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    sequence = sequence_document["seq"]
    return f"DPID{sequence:06}"


def add_department(department: Department) -> DepartmentInDB:
    dept_id = fetch_next_dept_id()
    department_data = department.dict()
    department_data["dept_id"] = dept_id
    department_collection.insert_one(department_data)
    return DepartmentInDB(**department_data)


@app.post("/superuser-departments/", response_model=DepartmentInDB)
def create_department(department: Department):
    department_in_db = add_department(department)
    return department_in_db


@app.put("/superuser--update/{admin_id}/{dept_id}", response_model=DepartmentInDB)
def update_department(admin_id: str, dept_id: str, department_update: DepartmentUpdate):
    updated_result = department_collection.find_one_and_update(
        {"admin_id": admin_id, "dept_id": dept_id},
        {"$set": {"dept_name": department_update.dept_name,
                  "updated_date": department_update.updated_date}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return DepartmentInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Department not found")


@app.patch("/superuser-status/{admin_id}/{dept_id}/status", response_model=DepartmentInDB)
def update_department_status(admin_id: str, dept_id: str, status_update: DepartmentStatusUpdate):
    updated_result = department_collection.find_one_and_update(
        {"admin_id": admin_id, "dept_id": dept_id},
        {"$set": {"status": status_update.status}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return DepartmentInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Department not found")


@app.get("/superuser-departments-show/{admin_id}/active", response_model=List[DepartmentInDB])
def get_active_departments_by_admin(admin_id: str):
    active_departments = department_collection.find(
        {"admin_id": admin_id, "status": "Active"})
    return [DepartmentInDB(**department) for department in active_departments]


# Sector
sector_collection = database.Sector
sequence_sector_collection = database.Sector_Sequence


class Sector(BaseModel):
    admin_id: str
    sector_name: str
    creation_date: datetime = Field(default_factory=datetime.utcnow)
    status: str = "Active"


class SectorInDB(Sector):
    sector_id: str
    updated_date: datetime = None


class SectorUpdate(BaseModel):
    sector_name: str
    updated_date: datetime = Field(default_factory=datetime.utcnow)


def fetch_next_sector_id():
    sequence_document = sequence_sector_collection.find_one_and_update(
        {"_id": "sector_id"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    sequence = sequence_document["seq"]
    return f"SECTID{sequence:06}"


def add_sector(sector: Sector) -> SectorInDB:
    sector_id = fetch_next_sector_id()
    sector_data = sector.dict()
    sector_data["sector_id"] = sector_id
    sector_collection.insert_one(sector_data)
    return SectorInDB(**sector_data)


@app.post("/admin-sectors/", response_model=SectorInDB)
def create_sector(sector: Sector):
    sector_in_db = add_sector(sector)
    return sector_in_db


@app.put("/superuser-update/{admin_id}/{sector_id}", response_model=SectorInDB)
def update_sector(admin_id: str, sector_id: str, sector_update: SectorUpdate):
    updated_result = sector_collection.find_one_and_update(
        {"admin_id": admin_id, "sector_id": sector_id},
        {"$set": {"sector_name": sector_update.sector_name,
                  "updated_date": sector_update.updated_date}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return SectorInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Sector not found")


@app.patch("/superuser-status/{admin_id}/{sector_id}/status", response_model=SectorInDB)
def update_sector_status(admin_id: str, sector_id: str, status_update: SectorStatusUpdate):
    updated_result = sector_collection.find_one_and_update(
        {"admin_id": admin_id, "sector_id": sector_id},
        {"$set": {"status": status_update.status}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return SectorInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Sector not found")


@app.get("/superuser-show/{admin_id}/active", response_model=List[SectorInDB])
def get_active_sectors_by_admin(admin_id: str):
    active_sectors = sector_collection.find(
        {"admin_id": admin_id, "status": "Active"})
    return [SectorInDB(**sector) for sector in active_sectors]


# Skill
skill_collection = database.Skill
sequence_skill_collection = database.Skill_Sequence


class Skill(BaseModel):
    admin_id: str
    skill_name: str
    creation_date: datetime = Field(default_factory=datetime.utcnow)
    status: str = "Active"


class SkillInDB(Skill):
    skill_id: str
    updated_date: datetime = None


class SkillUpdate(BaseModel):
    skill_name: str
    updated_date: datetime = Field(default_factory=datetime.utcnow)


def fetch_next_skill_id():
    sequence_document = sequence_skill_collection.find_one_and_update(
        {"_id": "skill_id"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    sequence = sequence_document["seq"]
    return f"SKILLID{sequence:06}"


def add_skill(skill: Skill) -> SkillInDB:
    skill_id = fetch_next_skill_id()
    skill_data = skill.dict()
    skill_data["skill_id"] = skill_id
    skill_collection.insert_one(skill_data)
    return SkillInDB(**skill_data)


@app.post("/superuser-skills/", response_model=SkillInDB)
def create_skill(skill: Skill):
    skill_in_db = add_skill(skill)
    return skill_in_db


@app.put("/superuser-skills-update/{admin_id}/{skill_id}", response_model=SkillInDB)
def update_skill(admin_id: str, skill_id: str, skill_update: SkillUpdate):
    updated_result = skill_collection.find_one_and_update(
        {"admin_id": admin_id, "skill_id": skill_id},
        {"$set": {"skill_name": skill_update.skill_name,
                  "updated_date": skill_update.updated_date}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return SkillInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Skill not found")


@app.patch("/superuser-skills-status/{admin_id}/{skill_id}/status", response_model=SkillInDB)
def update_skill_status(admin_id: str, skill_id: str, status_update: SkillStatusUpdate):
    updated_result = skill_collection.find_one_and_update(
        {"admin_id": admin_id, "skill_id": skill_id},
        {"$set": {"status": status_update.status}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return SkillInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Skill not found")


@app.get("/superuser-skills-show/{admin_id}/active", response_model=List[SkillInDB])
def get_active_skills_by_admin(admin_id: str):
    active_skills = skill_collection.find(
        {"admin_id": admin_id, "status": "Active"})
    return [SkillInDB(**skill) for skill in active_skills]

# ----------------------------------------------------------------------------------------------------------------------------------------


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class Role(str, Enum):
    organization = "Organization"
    student = "Student"


class UserSchema(BaseModel):
    email: EmailStr
    role: Role  # Use the Role enum here
    name: str
    mobile_number: str
    password: str
    confirm_password: str
    organization_id: Optional[str] = None  # New field for organization ID


class OTPVerificationSchema(BaseModel):
    email: EmailStr
    otp: int


class Token(BaseModel):
    access_token: str
    token_type: str
    organization_id: Optional[str] = None
    name: str
    role: Role
    email: EmailStr


class TokenData(BaseModel):
    email: Optional[str] = None


def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(email: str, password: str):
    user = users_collection.find_one({"email": email})
    if not user:
        return False
    if not verify_password(password, user['password']):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def send_email_otp(email: str, otp: int):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'Your OTP'

    body = f'Your OTP is: {otp}'
    message.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()


def save_user(user_data: UserSchema, hashed_password: str, otp: int):
    user_dict = user_data.dict()
    user_dict.pop('confirm_password')  # Remove confirm_password before saving
    user_dict['password'] = hashed_password
    user_dict['otp'] = otp
    user_dict['otp_expiry'] = datetime.utcnow(
    ) + timedelta(minutes=10)  # OTP expires in 10 minutes
    users_collection.insert_one(user_dict)


def generate_unique_organization_id(length=10):
    characters = string.ascii_uppercase + string.digits
    while True:
        organization_id = ''.join(random.choice(characters)
                                  for _ in range(length))
        if not users_collection.find_one({"organization_id": organization_id}):
            return organization_id


def send_password_reset_confirmation_email(email: str, name: str):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'Password Reset Confirmation'

    body = f'Hi {name},\n\nYour password has been successfully reset. If you did not initiate this change, please contact our support immediately.\n\nBest Regards,\nAI- Disha'
    message.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()


def send_welcome_email(email: str, name: str):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'Welcome to Our AI - Disha!'

    body = f'Hi {name},\n\nWelcome to AI- Disha!\nCongratulations you have Registered Successfully!!! \nWe are excited to have you on board.\n\nWe are glad you have registered to our platform. \nVisit: www.aidisha.com \n\nThanks & Regards,\nAI - Disha'
    message.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()


def get_client_ip(request: Request):
    client_host = request.client.host
    return client_host


def get_client_ip(request: Request):
    if "X-Forwarded-For" in request.headers:
        # In case there are multiple proxies, take the first one.
        return request.headers["X-Forwarded-For"].split(",")[0]
    return request.client.host


def send_new_device_login_email(email: str, ip: str, name: str):
    message = MIMEMultipart()
    message['From'] = EMAIL_ADDRESS
    message['To'] = email
    message['Subject'] = 'New Device Login Detected'

    body = f"""Hi {name},
    
A new login to your account was detected from a device using IP address {ip}.
If this was you, you can safely ignore this email. \nIf you do not recognize this login, we strongly recommend that you change your password immediately as your account may be compromised.

Best Regards,
AI- Disha"""
    message.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    text = message.as_string()
    server.sendmail(EMAIL_ADDRESS, email, text)
    server.quit()


@app.post("/admin-Register/")
async def send_otp(user_data: UserSchema):
    if user_data.password != user_data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")

    # Check if the email is already registered
    if users_collection.find_one({"email": user_data.email}):
        raise HTTPException(
            status_code=400, detail="Email already registered.")

    hashed_password = get_password_hash(user_data.password)
    otp = random.randint(100000, 999999)
    save_user(user_data, hashed_password, otp)
    send_email_otp(user_data.email, otp)

    return {"message": "OTP sent to the email. Please verify to complete registration."}


@app.post("/admin-Register-Verify-OTP/")
async def verify_otp(otp_data: OTPVerificationSchema):
    user = users_collection.find_one({"email": otp_data.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    current_time = datetime.utcnow()
    if user.get('otp') == otp_data.otp and current_time < user.get('otp_expiry'):
        update_data = {"is_verified": True}
        if user.get('role') == Role.organization:
            organization_id = generate_unique_organization_id()
            update_data["organization_id"] = organization_id
        users_collection.update_one(
            {"email": otp_data.email}, {"$set": update_data})

        # Send welcome email
        send_welcome_email(otp_data.email, user['name'])

        return {"message": "OTP verified successfully. Registration complete."}
    else:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")


@app.post("/admin-Login", response_model=Token)
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    email = form_data.username  # Treat the 'username' field as the user's email
    password = form_data.password

    user = authenticate_user(email, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Continue with your existing logic...

    # Example function to get client IP - implement this based on your requirements
    client_ip = get_client_ip(request)

    # Check if IP is new
    if client_ip not in user.get('known_ips', []):
        # If new, update known IPs and send email
        users_collection.update_one({"email": user['email']}, {
                                    "$addToSet": {"known_ips": client_ip}})
        send_new_device_login_email(user['email'], client_ip, user['name'])

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['email']}, expires_delta=access_token_expires
    )

    # Extract additional information from the user object
    organization_id = user.get('organization_id')
    name = user.get('name')
    role = user.get('role')
    email = user['email']

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "organization_id": organization_id,
        "name": name,
        "role": role,
        "email": email
    }


@app.post("/admin-Forget-Password-Email/")
async def password_reset_send_otp(email: EmailStr):
    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="Email not found.")

    # Generate and save OTP
    otp = random.randint(100000, 999999)
    otp_expiry = datetime.utcnow() + timedelta(minutes=10)  # OTP expires in 10 minutes
    users_collection.update_one(
        {"email": email}, {"$set": {"reset_otp": otp, "reset_otp_expiry": otp_expiry}})

    # Send OTP to user's email
    send_email_otp(email, otp)

    return {"message": "OTP sent to the email. Please verify to proceed with password reset."}


@app.post("/admin-Forget-Password/Verify-OTP/")
async def password_reset_verify_otp(otp_data: OTPVerificationSchema):
    user = users_collection.find_one({"email": otp_data.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    current_time = datetime.utcnow()
    if user.get('reset_otp') == otp_data.otp and current_time < user.get('reset_otp_expiry'):
        # Optionally, you could mark the OTP as used here to prevent reuse
        return {"message": "OTP verified successfully. You may now reset your password."}
    else:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")


@app.post("/admin-Password-Reset/")
async def password_reset(otp_data: OTPVerificationSchema, new_password: str, confirm_password: str):
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")

    user = users_collection.find_one({"email": otp_data.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    current_time = datetime.utcnow()
    if user.get('reset_otp') == otp_data.otp and current_time < user.get('reset_otp_expiry'):
        hashed_password = get_password_hash(new_password)
        users_collection.update_one({"email": otp_data.email}, {
                                    "$set": {"password": hashed_password}})
        # Optionally, clear the OTP fields here to prevent reuse

        # Send password reset confirmation email
        send_password_reset_confirmation_email(otp_data.email, user['name'])

        return {"message": "Password reset successfully."}
    else:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")


# ----------------------------------ADMIN DEPARTMENT / ADMIN SEQUENCE / SKILL------------------------------------------------------------------------

class Status(str, Enum):
    active = "Active"
    inactive = "Inactive"


class DepartmentStatusUpdate(BaseModel):
    status: Status


class SectorStatusUpdate(BaseModel):
    status: Status


class SkillStatusUpdate(BaseModel):
    status: Status

# MongoDB connection details
# MONGO_DETAILS = "mongodb+srv://somnath:somnath@cluster0.izhugny.mongodb.net/"
# client = MongoClient(MONGO_DETAILS)
# database = client.Admin_Module
# mycol = database.city_management

# app = FastAPI()


# Department
department_collection = database.Dept
sequence_department_collection = database.Dept_Sequence


class Department(BaseModel):
    admin_id: str
    dept_name: str
    creation_date: datetime = Field(default_factory=datetime.utcnow)
    status: str = "Active"


class DepartmentInDB(Department):
    dept_id: str
    updated_date: datetime = None


class DepartmentUpdate(BaseModel):
    dept_name: str
    updated_date: datetime = Field(default_factory=datetime.utcnow)


def fetch_next_dept_id():
    sequence_document = sequence_department_collection.find_one_and_update(
        {"_id": "dept_id"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    sequence = sequence_document["seq"]
    return f"DPID{sequence:06}"


def add_department(department: Department) -> DepartmentInDB:
    dept_id = fetch_next_dept_id()
    department_data = department.dict()
    department_data["dept_id"] = dept_id
    department_collection.insert_one(department_data)
    return DepartmentInDB(**department_data)


@app.post("/admin-departments/", response_model=DepartmentInDB)
def create_department(department: Department):
    department_in_db = add_department(department)
    return department_in_db


@app.put("/admin-departments-update/{admin_id}/{dept_id}", response_model=DepartmentInDB)
def update_department(admin_id: str, dept_id: str, department_update: DepartmentUpdate):
    updated_result = department_collection.find_one_and_update(
        {"admin_id": admin_id, "dept_id": dept_id},
        {"$set": {"dept_name": department_update.dept_name,
                  "updated_date": department_update.updated_date}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return DepartmentInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Department not found")


@app.patch("/admin-departments-status/{admin_id}/{dept_id}/status", response_model=DepartmentInDB)
def update_department_status(admin_id: str, dept_id: str, status_update: DepartmentStatusUpdate):
    updated_result = department_collection.find_one_and_update(
        {"admin_id": admin_id, "dept_id": dept_id},
        {"$set": {"status": status_update.status}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return DepartmentInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Department not found")


@app.get("/admin-departments-show/{admin_id}/active", response_model=List[DepartmentInDB])
def get_active_departments_by_admin(admin_id: str):
    active_departments = department_collection.find(
        {"admin_id": admin_id, "status": "Active"})
    return [DepartmentInDB(**department) for department in active_departments]


# Sector
sector_collection = database.Sector
sequence_sector_collection = database.Sector_Sequence


class Sector(BaseModel):
    admin_id: str
    sector_name: str
    creation_date: datetime = Field(default_factory=datetime.utcnow)
    status: str = "Active"


class SectorInDB(Sector):
    sector_id: str
    updated_date: datetime = None


class SectorUpdate(BaseModel):
    sector_name: str
    updated_date: datetime = Field(default_factory=datetime.utcnow)


def fetch_next_sector_id():
    sequence_document = sequence_sector_collection.find_one_and_update(
        {"_id": "sector_id"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    sequence = sequence_document["seq"]
    return f"SECTID{sequence:06}"


def add_sector(sector: Sector) -> SectorInDB:
    sector_id = fetch_next_sector_id()
    sector_data = sector.dict()
    sector_data["sector_id"] = sector_id
    sector_collection.insert_one(sector_data)
    return SectorInDB(**sector_data)


@app.post("/admin-sectors/", response_model=SectorInDB)
def create_sector(sector: Sector):
    sector_in_db = add_sector(sector)
    return sector_in_db


@app.put("/admin-sectors-update/{admin_id}/{sector_id}", response_model=SectorInDB)
def update_sector(admin_id: str, sector_id: str, sector_update: SectorUpdate):
    updated_result = sector_collection.find_one_and_update(
        {"admin_id": admin_id, "sector_id": sector_id},
        {"$set": {"sector_name": sector_update.sector_name,
                  "updated_date": sector_update.updated_date}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return SectorInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Sector not found")


@app.patch("/admin-sectors-status/{admin_id}/{sector_id}/status", response_model=SectorInDB)
def update_sector_status(admin_id: str, sector_id: str, status_update: SectorStatusUpdate):
    updated_result = sector_collection.find_one_and_update(
        {"admin_id": admin_id, "sector_id": sector_id},
        {"$set": {"status": status_update.status}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return SectorInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Sector not found")


@app.get("/admin-sectors-show/{admin_id}/active", response_model=List[SectorInDB])
def get_active_sectors_by_admin(admin_id: str):
    active_sectors = sector_collection.find(
        {"admin_id": admin_id, "status": "Active"})
    return [SectorInDB(**sector) for sector in active_sectors]


# Skill
skill_collection = database.Skill
sequence_skill_collection = database.Skill_Sequence


class Skill(BaseModel):
    admin_id: str
    skill_name: str
    creation_date: datetime = Field(default_factory=datetime.utcnow)
    status: str = "Active"


class SkillInDB(Skill):
    skill_id: str
    updated_date: datetime = None


class SkillUpdate(BaseModel):
    skill_name: str
    updated_date: datetime = Field(default_factory=datetime.utcnow)


def fetch_next_skill_id():
    sequence_document = sequence_skill_collection.find_one_and_update(
        {"_id": "skill_id"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    sequence = sequence_document["seq"]
    return f"SKILLID{sequence:06}"


def add_skill(skill: Skill) -> SkillInDB:
    skill_id = fetch_next_skill_id()
    skill_data = skill.dict()
    skill_data["skill_id"] = skill_id
    skill_collection.insert_one(skill_data)
    return SkillInDB(**skill_data)


@app.post("/admin-skills/", response_model=SkillInDB)
def create_skill(skill: Skill):
    skill_in_db = add_skill(skill)
    return skill_in_db


@app.put("/admin-skills-update/{admin_id}/{skill_id}", response_model=SkillInDB)
def update_skill(admin_id: str, skill_id: str, skill_update: SkillUpdate):
    updated_result = skill_collection.find_one_and_update(
        {"admin_id": admin_id, "skill_id": skill_id},
        {"$set": {"skill_name": skill_update.skill_name,
                  "updated_date": skill_update.updated_date}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return SkillInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Skill not found")


@app.patch("/admin-skills-status/{admin_id}/{skill_id}/status", response_model=SkillInDB)
def update_skill_status(admin_id: str, skill_id: str, status_update: SkillStatusUpdate):
    updated_result = skill_collection.find_one_and_update(
        {"admin_id": admin_id, "skill_id": skill_id},
        {"$set": {"status": status_update.status}},
        return_document=ReturnDocument.AFTER
    )
    if updated_result:
        return SkillInDB(**updated_result)
    else:
        raise HTTPException(status_code=404, detail="Skill not found")


@app.get("/admin-skills-show/{admin_id}/active", response_model=List[SkillInDB])
def get_active_skills_by_admin(admin_id: str):
    active_skills = skill_collection.find(
        {"admin_id": admin_id, "status": "Active"})
    return [SkillInDB(**skill) for skill in active_skills]


# --------------------------------------------------CITY MANAGEMENT--------------------------------------------------------------------

"""# Define function to generate city ID
def generate_city_id():
    # Generate a random six-digit number
    random_number = random.randint(100000, 999999)
    # Create the city ID with the format "city" followed by the random six-digit number
    city_id = f"city{random_number}"
    return city_id

# Define route to insert city data
@app.post("/insert-city/")
def insert_city_data(city_name: str, state: str, district: str, pin_code: int):
    city_id = generate_city_id()
    creation_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    city_data = {
        "city_id": city_id,
        "city_name": city_name,
        "state": state,
        "district": district,
        "pin_code": pin_code,
        "creation_date": creation_date
    }

    # Insert the city_data into the MongoDB collection
    city_result = mycol.insert_one(city_data)

    if city_result.inserted_id:
        return {"message": "City data inserted successfully", "city_id": city_id}
    else:
        raise HTTPException(status_code=500, detail="Failed to insert city data")

# Define route to delete city data (soft delete)
@app.delete("/delete-city/")
def delete_city_data(city_id: str):
    # Find the city document with the provided city ID
    city_query = {"city_id": city_id}
    city_data = mycol.find_one(city_query)

    if city_data:
        # Update the deletion time for the city document
        deletion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        update_result = mycol.update_one(city_query, {"$set": {"deletion_date": deletion_time}})

        if update_result.modified_count > 0:
            return {"message": "City data soft deleted successfully", "city_id": city_id}
        else:
            raise HTTPException(status_code=500, detail="Failed to soft delete city data")
    else:
        raise HTTPException(status_code=404, detail="City ID not found")

"""

# -------------------------------------------------ROLE MANAGEMENT----------------------------------------------------------------------


# Connect to MongoDB
# client = MongoClient(MONGO_DETAILS)
db1 = client.Role_Management
mycol = db1.role
org_ids_collection = db1.role_sequence

# app = FastAPI()

# Define function to generate a unique Role_ID with the prefix "rid-"


def generate_role_id(org_id: int):
    # Find the maximum Role_ID for the given Org_ID
    max_role_id = org_ids_collection.find_one(
        {"Org_ID": org_id}, sort=[("Role_ID", -1)])
    if max_role_id:
        # Extract the numeric part of the maximum Role_ID
        max_id_numeric = int(max_role_id["Role_ID"].split('-')[1])
        # Increment the numeric part
        next_id_numeric = max_id_numeric + 1
    else:
        # If no Role_ID found for the given Org_ID, start from 1
        next_id_numeric = 1

    # Format the numeric part with leading zeros
    next_id_formatted = f"{next_id_numeric:06}"

    # Construct the next unique Role_ID
    role_id = f"rid-{next_id_formatted}"

    return role_id


# Define route to insert a record into the MongoDB collection
@app.post("/Org-Role-Create/")
def insert_record(Role_Name: str, org_id: int, is_active: str = "Active"):
    # Check if the Role_Name already exists
    existing_role = mycol.find_one({"Role_Name": Role_Name})
    if existing_role:
        raise HTTPException(status_code=400, detail="Role name already exists")

    # Generate a unique Role_ID with the prefix "rid-" based on the Org_ID
    current_max_id = generate_role_id(org_id)

    # Create a dictionary with record data
    record_dict = {
        "Role_ID": current_max_id,
        "Org_ID": org_id,
        "Role_Name": Role_Name,
        "Creation_Date": datetime.now(),
        "isActive": is_active  # Default is active (Active), change if required
    }

    # Insert Org_ID and Role_ID into the Org_IDs collection
    org_ids_collection.insert_one(
        {"Org_ID": org_id, "Role_ID": current_max_id})

    # Insert record into MongoDB collection
    mycol.insert_one(record_dict)

    return {"message": "Record inserted successfully", "Role_ID": current_max_id, "Role_Name": Role_Name, "Org_ID": org_id, "isActive": is_active}


# Define route to update a record in the MongoDB collection
@app.put("/Org-Role-Edit/")
def Update_record(Org_ID: int, Role_ID: str, Role_Name: str):
    # Define the query to find the record to update
    myquery = {'Org_ID': Org_ID, 'Role_ID': Role_ID}
    # Define the update operation using $set method
    newvalues = {
        '$set': {
            "Role_Name": Role_Name,
            "Last_Update_Date": datetime.now()  # Update the Last_Update_Date field
        }
    }
    # Update the record in the MongoDB collection
    result = mycol.update_one(myquery, newvalues)
    if result.modified_count == 1:
        return {"message": "Record updated successfully", "Role_Name": Role_Name, "Role_ID": Role_ID, 'Org_ID': Org_ID, "Last_Update_Date": datetime.now(), "Creation_Date": datetime.now(), }
    else:
        raise HTTPException(status_code=404, detail="Record not found")


# Define route to update the status of a record based on Org_ID and Role_ID
@app.put("/Org-Role-status/")
def update_status(Org_ID: int, Role_ID: str, new_status: str):
    # Find the record based on Org_ID and Role_ID
    query = {"Org_ID": Org_ID, "Role_ID": Role_ID}
    record = mycol.find_one(query)

    if record:
        # Update the status field of the record
        mycol.update_one(query, {"$set": {"isActive": new_status}})

        # Construct the response JSON
        return {"Org_ID": Org_ID,
                "Role_ID": Role_ID,
                "isActive": new_status}
    else:
        raise HTTPException(status_code=404, detail="Record not found")

# Define route to fetch active records based on Org_ID


@app.get("/Org-Role-Show/")
def get_active_records_by_org_id(Org_ID: int):
    # Find active records in the collection based on Org_ID
    query = {"Org_ID": Org_ID, "isActive": "Active"}
    records = mycol.find(query)

    if records:
        # List to store formatted active records
        formatted_records = []
        for record in records:
            # Extract necessary fields from each record
            role_id = record.get("Role_ID", "Unknown")
            role_name = record.get("Role_Name", "Unknown")
            creation_date = record.get("Creation_Date", "Unknown")
            status = record.get("isActive", "Unknown")

            # Construct the response JSON for each active record
            formatted_record = {
                "Org_ID": Org_ID,
                "Role_ID": role_id,
                "Role_Name": role_name,
                "Creation_Date": creation_date,
                "Status": status
                # Add other fields as needed
            }
            formatted_records.append(formatted_record)

        # Construct the response JSON containing all active records based on Org_ID
        response_data = {
            "message": f"All active records for Org_ID {Org_ID} retrieved successfully",
            "active_records": formatted_records
        }
        return response_data
    else:
        raise HTTPException(
            status_code=404, detail=f"No active records found for Org_ID {Org_ID}")


# ------------------------------------------------USER MANAGEMENT-----------------------------------------------------------

def find_users_count(org_id):
    cnt = mycol1.count_documents({"organisation_id": org_id})
    return cnt


def create_uid(str_org, n):
    user_num = n+1
    print(user_num)
    str1 = ""
    if user_num < 10:
        str1 = f'00000{user_num}'
    else:
        if (user_num > 10 and user_num < 100):
            str1 = f'0000{user_num}'
        else:
            if (user_num > 100 and user_num < 1000):
                str1 = f'000{user_num}'
            else:
                if (user_num > 1000 and user_num < 10000):
                    str1 = f'00{user_num}'
                else:
                    if (user_num > 10000 and user_num < 100000):
                        str1 = f'0{user_num}'
                    else:
                        str1 = f'{user_num}'

    uid_str = "U-" + str_org + "-" + str1
    return (uid_str)

# --------------/users_get_by_organisation------------


@app.get("/org-all_users{org_id}")
def get_all_users(org_id):
    query = {"organisation_id": org_id, "status": "active"}
    result = mycol1.find(query)
    if result:
        uidlist = []
        namelist = []
        emaillist = []
        moblist = []
        citylist = []
        statelist = []
        deptlist = []
        rolelist = []
        jdatelist = []
        genderlist = []
        doblist = []
        addresslist = []
        aadharlist = []
        panlist = []

        for document in result:
            uidlist.append(document["uid"])
            namelist.append(document["name"])
            emaillist.append(document["email"])
            moblist.append(document["mobile"])
            citylist.append(document["city"])
            statelist.append(document["state"])
            deptlist.append(document["department"])
            rolelist.append(document["role"])
            jdatelist.append(document["joining_date"])
            genderlist.append(document["gender"])
            doblist.append(document["dob"])
            addresslist.append(document["address"])
            aadharlist.append(document["aadhar_no"])
            panlist.append(document["PAN"])

        row_data = []

        for i in range(len(uidlist)):
            row_data.append({"uid": uidlist[i], "name": namelist[i], "email": emaillist[i], "mobile": moblist[i], "Aadhar": aadharlist[i], "PAN": panlist[i], "gender": genderlist[i],
                            "dob": genderlist[i], "address": addresslist[i], "city": citylist[i], "state": statelist[i], "department": deptlist[i], "role": rolelist[i], "joining_date": jdatelist[i]})
        return row_data
    else:
        raise HTTPException(status_code=404, detail="Candidate not found")


# ----------- /user_post_new_user -----------------
# Endpoint to create a new user
@app.post('/org-create_user')
def create_data(organisation_id, name, gen, dob, email, address, aadhar, pan, mob, city, state, dept, password, role):
    today = datetime.utcnow()
    user_count = find_users_count(organisation_id)

    # Increment UID based on the maximum UID value from the user_sequence collection
    max_uid_record = user_sequence_collection.find_one(
        {"organisation_id": organisation_id}, sort=[("uid", -1)])
    if max_uid_record:
        max_uid = max_uid_record["uid"]
        max_user_num = int(max_uid.split("-")[-1])
    else:
        max_user_num = 0

    uid = create_uid(organisation_id, max_user_num)

    query1 = {"email": email}
    query2 = {"mobile": mob}

    if mycol1.find_one(query1) is None and mycol1.find_one(query2) is None:
        # Insert user record into the user collection
        doc = {
            "organisation_id": organisation_id,
            "uid": uid,
            "name": name,
            "gender": gen,
            "dob": dob,
            "email": email,
            "mobile": mob,
            "address": address,
            "aadhar_no": aadhar,
            "PAN": pan,
            "city": city,
            "state": state,
            "department": dept,
            "role": role,
            "password": password,
            "joining_date": today,
            "status": "active",
            "last_update": datetime.now(),
        }
        mycol1.insert_one(doc)

        # Update the user_sequence collection with the new UID
        user_sequence_collection.insert_one(
            {"organisation_id": organisation_id, "uid": uid})
        return f"User created successfully: {doc}"
    else:
        raise HTTPException(status_code=409, detail="Record already exists!")

# Example usage of the above code
# create_data("org123", "John Doe", "Male", "1990-01-01", "john@example.com", "Address", "1234567890", "ABCDE1234F", "9876543210", "City", "State", "Dept", "password", "Role")

# -------/user_update -----------


@app.put('/org-update_user')
def update_data(org_id, u_id, name, dob, gender, email, mob, PAN, aadhar, city, state, dept, password, role):
    # Check if the user with the given organization ID, UID, and status is active
    user = mycol1.find_one(
        {"organisation_id": org_id, "uid": u_id, "status": "active"})
    if user:
        # Create the updated document
        updated_doc = {
            "name": name,
            "dob": dob,
            "gender": gender,
            "email": email,
            "mobile": mob,
            "aadhar_no": aadhar,
            "PAN": PAN,
            "city": city,
            "state": state,
            "department": dept,
            "password": password,
            "role": role,
            "last_update": datetime.now()  # Corrected field name to "last_update"
        }
        # Update the document in the collection
        mycol1.update_one({"uid": u_id}, {"$set": updated_doc})
        return {"Message": f'User record updated successfully: {u_id}'}
    else:
        raise HTTPException(
            status_code=404, detail=f'Record does not exist - UID {u_id}')


# deactivate user
# --------/user_deactivate
@app.patch('/org-deactivate_user/{uid}')
def deactivate(uid):
    res = mycol1.find_one({"uid": uid})
    if res:
        if res["status"] == "active":
            mycol1.update_one(
                {"uid": uid}, {"$set": {"status": "inactive", "last_update": datetime.now()}})
            return {"Message": f'User record deactivated successfully: {uid}'}
        else:
            mycol1.update_one(
                {"uid": uid}, {"$set": {"status": "active", "last_update": datetime.now()}})
            return {"Message": f'User record revoked to active successfully: {uid}'}
    else:
        raise HTTPException(
            status_code=404, detail=f'Record does not exist - UID {uid}')


# ---------------------------------------DEPART MANAGEMENT-------------------------------------------------------


class Status(Enum):
    Active = "Active"
    Inactive = "Inactive"

# Function to get the next department_id for a given organisation_id


def get_next_department_id(organisation_id):
    sequence = dept_sequence_collection.find_one(
        {"organisation_id": organisation_id})
    if sequence:
        next_department_id = sequence["department_id"] + 1
    else:
        next_department_id = 1  # Start from 1 if no sequence exists
    return next_department_id

# Route to insert a department


@app.post('/org-insert-department')
def create_department(organisation_id: int, department_name: str):
    next_department_id = get_next_department_id(organisation_id)
    today = datetime.now()
    status = Status.Active.value  # Get the value of the enum
    department = {
        "organisation_id": organisation_id,
        "department_id": next_department_id,
        "department_name": department_name,
        "creation_date": today,
        "update_date": today,
        "status": status  # Store the value of the enum as a string
    }
    mycol2.insert_one(department)

    # Update dept_sequence with the new maximum department_id
    dept_sequence_collection.update_one(
        {"organisation_id": organisation_id},
        {"$set": {"department_id": next_department_id}},
        upsert=True  # Insert if not exists
    )

    return {"message": "Department created successfully"}

# Route to edit a department


@app.put('/org-edit-department/{organisation_id}/{department_id}')
def edit_department(organisation_id: int, department_id: int, department_name: str):
    department = mycol2.find_one(
        {"organisation_id": organisation_id, "department_id": department_id})
    if not department:
        raise HTTPException(status_code=404, detail="Department not found")
    previous_department = department.copy()
    today = datetime.now()
    result = mycol2.update_one(
        {"organisation_id": organisation_id, "department_id": department_id},
        {"$set": {"department_name": department_name, "update_date": today}}
    )
    if result.modified_count == 1:
        # Convert ObjectId to string for JSON serialization
        previous_department['_id'] = str(previous_department['_id'])
        return {"message": "Department updated successfully", "previous_department": previous_department}
    else:
        return {"message": "Department not updated"}

# Route to update department status


@app.put('/org-update-department-status/{organisation_id}/{department_id}')
def update_department_status(organisation_id: int, department_id: int, status: Status):
    department = mycol2.find_one(
        {"organisation_id": organisation_id, "department_id": department_id})
    if not department:
        raise HTTPException(status_code=404, detail="Department not found")
    previous_department = department.copy()
    previous_department['_id'] = str(
        previous_department['_id'])  # Convert ObjectId to string
    today = datetime.now()
    result = mycol2.update_one(
        {"organisation_id": organisation_id, "department_id": department_id},
        {"$set": {"status": status.value, "update_date": today}}
    )
    if result.modified_count == 1:
        return {"message": f"Department status updated to {status}", "previous_department": previous_department}
    else:
        return {"message": "Department status not updated"}

# Route to get departments


@app.get('/org-get-departments')
def get_departments(organisation_id: int = Query(None, description="Select organisation ID")):
    if not organisation_id:
        departments = list(mycol2.find())
    else:
        departments = list(mycol2.find({"organisation_id": organisation_id}))

    for department in departments:
        department['_id'] = str(department['_id'])
    min_department_id = min(department['department_id']
                            for department in departments)
    organization_ids = set(department['organisation_id']
                           for department in departments)
    return {"departments": departments, "min_department_id": min_department_id, "organisation_ids": list(organization_ids)}

# ----------------------------------------------JOB DESCRIPTION------------------------------------------------------------

# Define function to generate a unique job ID with the format "jid-000001"


def generate_custom_job_id():
    # Generate a random six-digit number
    random_number = random.randint(1, 999999)
    # Format the random number with leading zeros
    job_id_numeric = f"{random_number:06}"
    # Create the custom job ID with the format "jid-" followed by the formatted random six-digit number
    custom_job_id = f"jid-{job_id_numeric}"
    return custom_job_id


# Define route to get the details of job descriptions by organization ID
@app.post("/org-insert-job/")
def insert_job_description(
    org_id: str,
    job_title: str,
    city: str,
    salary_range: str,
    job_description: str,
    required_skills: str,
    functional_area: str,
    company_info: str,
    experience_years: int,
    state: str,
    employee_type: str,
    responsibility: str,
    status: str = "active",  # Set default value to "active"
    additional_skills: Optional[str] = None,
    education: Optional[str] = None,
    benefits: Optional[str] = None
):
    # Generate custom job ID
    job_id = generate_custom_job_id()

    # Create dictionaries with job and organization data
    job_description_data = {
        "Job_ID": str(job_id),  # Convert job_id to string
        "Org_ID": org_id,
        "Job_Title": job_title,
        "City": city,
        "Salary_Range": salary_range,
        "Job_Description": job_description,
        "Required_Skills": required_skills,
        "Functional_Area": functional_area,
        "Company_Info": company_info,
        "Experience_Years": experience_years,
        "State": state,
        "Employee_Type": employee_type,
        "Responsibility": responsibility,
        "Additional_Skills": additional_skills,
        "Education": education,
        "Benefits": benefits,
        "Creation_Date": datetime.now(),
        "Status": status,  # Set status
        "Deleted": False
    }

    org_data = {
        "Org_ID": org_id,
        "Name": company_info,
    }

    # Insert job and organization data into MongoDB collections
    job_result = mycol3.insert_one(job_description_data)
    org_result = mycol3.organizations.insert_one(org_data)

    if job_result.inserted_id and org_result.inserted_id:
        return {"message": "Job description and organization inserted successfully", "Job_ID": str(job_id), "Org_ID": org_id}
    else:
        raise HTTPException(
            status_code=500, detail="Failed to insert job description and organization")


# Define route to update a job description in the MongoDB collection
@app.put("/org-update-job/")
def update_job_description(
    Job_ID: str,
    org_id: str,
    job_title: Optional[str] = None,
    city: Optional[str] = None,
    salary_range: Optional[str] = None,
    job_description: Optional[str] = None,
    required_skills: Optional[str] = None,
    functional_area: Optional[str] = None,
    company_info: Optional[str] = None,
    experience_years: Optional[int] = None,
    state: Optional[str] = None,
    employee_type: Optional[str] = None,
    responsibility: Optional[str] = None,
    additional_skills: Optional[str] = None,
    education: Optional[str] = None,
    benefits: Optional[str] = None
):
    # Check if the status is active
    job_data = mycol3.find_one({"Job_ID": Job_ID, "Org_ID": org_id})
    if job_data and job_data["Status"] == "active":
        # Define the query to find the job description to update
        myquery = {'Job_ID': Job_ID, 'Org_ID': org_id}

        # Create a dictionary to hold only the fields that are not None
        newvalues = {}
        if job_title is not None:
            newvalues["Job_Title"] = job_title
        if city is not None:
            newvalues["City"] = city
        if salary_range is not None:
            newvalues["Salary_Range"] = salary_range
        if job_description is not None:
            newvalues["Job_Description"] = job_description
        if required_skills is not None:
            newvalues["Required_Skills"] = required_skills
        if functional_area is not None:
            newvalues["Functional_Area"] = functional_area
        if company_info is not None:
            newvalues["Company_Info"] = company_info
        if experience_years is not None:
            newvalues["Experience_Years"] = experience_years
        if state is not None:
            newvalues["State"] = state
        if employee_type is not None:
            newvalues["Employee_Type"] = employee_type
        if responsibility is not None:
            newvalues["Responsibility"] = responsibility
        if additional_skills is not None:
            newvalues["Additional_Skills"] = additional_skills
        if education is not None:
            newvalues["Education"] = education
        if benefits is not None:
            newvalues["Benefits"] = benefits

        # If no fields are provided to update, raise an HTTPException
        if not newvalues:
            raise HTTPException(
                status_code=400, detail="No fields provided for update")

        # Add Last_Update_Date to newvalues
        newvalues["Last_Update_Date"] = datetime.now()

        # Update the job description in the MongoDB collection
        result = mycol3.update_one(myquery, {"$set": newvalues})
        if result.modified_count == 1:
            return {"message": "Job description updated successfully", "Job_ID": Job_ID, "Org_ID": org_id}
        else:
            raise HTTPException(
                status_code=404, detail="Job description not found")
    else:
        raise HTTPException(
            status_code=400, detail="Job status is not active, cannot update job description")


"""# Define route to delete a job description in the MongoDB collection
@app.delete("/org-delete-job/")
def delete_job_description(Job_ID: str, org_id: str):
    # Find the job description to delete
    query = {"Job_ID": Job_ID, "Org_ID": org_id}

    # Fetch the job description
    job_description = mycol3.find_one(query)

    if job_description:
        # Check if the job status is already inactive
        if job_description["Status"] == "inactive":
            raise HTTPException(status_code=400, detail="Job status is already inactive, no need to delete")

        # Update the job description to mark as inactive and store the deletion timestamp
        newvalues = {
            '$set': {
                "Status": "inactive",
                "Deletion_Date": datetime.now()  
            }
        }
        result = mycol3.update_one(query, newvalues)

        if result.modified_count == 1:
            # Fetch the updated document to include the status field in the response
            updated_job_description = mycol3.find_one({"Job_ID": Job_ID, "Org_ID": org_id})
            if updated_job_description:
                return {
                    "message": "Job description marked as inactive successfully",
                    "Org_ID": org_id,
                    "Job_ID": Job_ID,
                    "Status": updated_job_description.get("Status"),  # Include the status in the response
                    "Deletion_Date": updated_job_description.get("Deletion_Date")
                }
            else:
                raise HTTPException(status_code=404, detail="Job description not found")
        else:
            raise HTTPException(status_code=404, detail="Job description not found")
    else:
        raise HTTPException(status_code=404, detail="Job description not found")
"""


# Define route to update the status of a job description
@app.patch("/org-update-job-status/")
def update_job_status(Job_ID: str, org_id: str, status: str):
    # Define the query to find the job description to update
    query = {'Job_ID': Job_ID, 'Org_ID': org_id}

    # Validate status value
    if status not in ["active", "inactive"]:
        raise HTTPException(
            status_code=400, detail="Invalid status value. Allowed values: active, inactive")

    # Create a dictionary with the status to update
    newvalues = {"$set": {"Status": status}}

    # Update the status of the job description in the MongoDB collection
    result = mycol3.update_one(query, newvalues)

    if result.modified_count == 1:
        return {"message": "Job status updated successfully", "Job_ID": Job_ID, "Org_ID": org_id, "Status": status}
    else:
        raise HTTPException(
            status_code=404, detail="Job description not found")


# Define route to get the status of job descriptions by organization ID
@app.get("/org-job-status/")
def get_job_status(org_id: str) -> List[dict]:
    # Find active job descriptions by organization ID
    job_descriptions = mycol3.find({"Org_ID": org_id, "Status": "active"}, {
                                   "_id": 0, "Job_ID": 1, "Status": 1})

    # Create a list to store active job statuses
    job_statuses = []
    for job in job_descriptions:
        job_statuses.append(job)

    return job_statuses


# Run the FastAPI application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
