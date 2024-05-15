from fastapi import FastAPI, HTTPException, status, Depends, APIRouter, Body
from pydantic import BaseModel
from typing import Optional
import sqlite3
import hashlib
import os
from random import randint
from datetime import datetime, timedelta
import smtplib
from mangum import Mangum
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from random import randint

app = FastAPI()
handler = Mangum(app)
# Database connection and table creation logic here (same as before)
load_dotenv()

# Database setup and connection
def create_connection(db_file):
    """Create a database connection to the SQLite database specified by db_file"""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except sqlite3.Error as e:
        print(e)
    return conn

def create_table(conn):
    """Create a table from the create_table_sql statement"""
    try:
        sql_create_table = """
        CREATE TABLE IF NOT EXISTS users (
            id integer PRIMARY KEY,
            username text NOT NULL UNIQUE,
            email text NOT NULL UNIQUE,
            password text NOT NULL,
            registration_otp integer,
            email_verified integer DEFAULT 0,
            failed_attempts integer DEFAULT 0,
            last_attempt_time datetime,
            reset_otp integer
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_table)
        conn.commit()
    except sqlite3.Error as e:
        print(e)

class ForgotPasswordRequest(BaseModel):
    username: str
    email: str

class ResetPasswordRequest(BaseModel):
    username: str
    otp: int
    new_password: str

# Pydantic models for request bodies
class SignupUser(BaseModel):
    username: str
    email: str
    password: str

class VerifyUser(BaseModel):
    email: str
    otp: int

class LoginUser(BaseModel):
    username: str
    password: str

class DeleteUserRequest(BaseModel):
    username: str
    password: str

def send_otp_email(receiver_email):
    """ Send an OTP to the specified email and return the OTP """
    sender_email = os.getenv("EMAIL_USER")
    sender_password = os.getenv("EMAIL_PASSWORD")
    otp = randint(100000, 999999)  # Generate a 6-digit OTP

    # Setup the MIME
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = 'Your OTP for Signup'
    msg_body = f"Hello, your OTP for registration is: {otp}"
    message.attach(MIMEText(msg_body, 'plain'))

    # Create SMTP session
    server = smtplib.SMTP('smtp.gmail.com', 587)  # Use 465 for SSL
    server.starttls()
    server.login(sender_email, sender_password)
    text = message.as_string()
    server.sendmail(sender_email, receiver_email, text)
    server.quit()

    return otp
# Signup function

def signup(conn, username, email, password):
    """Register a new user with email verification"""
    otp = send_otp_email(email)
    user_otp = input("Enter the OTP sent to your email: ")
    if str(otp) == user_otp:
        try:
            cursor = conn.cursor()
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            cursor.execute("INSERT INTO users(username, email, password) VALUES(?, ?, ?)", (username, email, hashed_password))
            conn.commit()
            print("Signup successful!")
            return True
        except sqlite3.IntegrityError as e:
            print(f"Error: {e}")
            return False
    else:
        print("Invalid OTP. Registration failed.")
        return False


# Login function with rate limiting
def login(conn, username, password):
    """Attempt to login a user with rate limiting"""
    cursor = conn.cursor()
    cursor.execute("SELECT password, failed_attempts, last_attempt_time FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user:
        stored_password, failed_attempts, last_attempt_time = user
        current_time = datetime.now()

        if last_attempt_time is not None:
            last_attempt_time = datetime.strptime(last_attempt_time, '%Y-%m-%d %H:%M:%S')

        # Check if the account is currently locked
        if last_attempt_time and (current_time - last_attempt_time < timedelta(minutes=5)) and failed_attempts >= 3:
            print("Login attempt blocked due to too many failed attempts. Please try again later.")
            return False

        if hashlib.sha256(password.encode()).hexdigest() == stored_password:
            cursor.execute("UPDATE users SET failed_attempts = 0, last_attempt_time = NULL WHERE username = ?", (username,))
            conn.commit()
            print("Login successful!")
            return True
        else:
            new_attempts = failed_attempts + 1
            cursor.execute("UPDATE users SET failed_attempts = ?, last_attempt_time = ? WHERE username = ?", (new_attempts, current_time.strftime('%Y-%m-%d %H:%M:%S'), username))
            conn.commit()
            print("Login failed. Incorrect username or password.")
            return False
    else:
        print("Login failed. User does not exist.")
        return False


def delete_user(conn, username):
    """ Delete a user from the database based on the username """
    try:
        cursor = conn.cursor()
        # Delete the user where the username matches
        cursor.execute("DELETE FROM users WHERE username=?", (username,))
        conn.commit()
        if cursor.rowcount == 0:
            print("No user found with that username.")
            return False
        else:
            print("User deleted successfully.")
            return True
    except sqlite3.Error as e:
        print(f"Error deleting user: {e}")
        return False

# Endpoints

@app.post("/signup/")
def signup(user: SignupUser):
    conn = create_connection("user_data.db")
    if conn is not None:
        cursor = conn.cursor()
        # Check if the username or email already exists
        cursor.execute("SELECT username, email FROM users WHERE username = ? OR email = ?", (user.username, user.email))
        existing_user = cursor.fetchone()
        
        if existing_user:
            # Determine which attribute is already in use
            if existing_user[0] == user.username:
                detail = "Username already exists."
            else:
                detail = "Email already registered."
            raise HTTPException(status_code=400, detail=detail)

        # Proceed with creating the new user if no conflicts are found
        hashed_password = hashlib.sha256(user.password.encode()).hexdigest()
        try:
            cursor.execute("INSERT INTO users(username, email, password, email_verified) VALUES(?, ?, ?, 0)", (user.username, user.email, hashed_password))
            conn.commit()
            return {"message": "Signup successful. Please verify your email to complete registration."}
        except sqlite3.IntegrityError as e:
            raise HTTPException(status_code=500, detail=f"Database error: {e}")
    else:
        raise HTTPException(status_code=500, detail="Database connection error.")

@app.post("/verify-email/")
def verify_email(verification: VerifyUser):
    conn = create_connection("user_data.db")
    if conn is not None:
        cursor = conn.cursor()
        cursor.execute("SELECT registration_otp FROM users WHERE email = ?", (verification.email,))
        record = cursor.fetchone()
        if record and record[0] == verification.otp:
            cursor.execute("UPDATE users SET email_verified = 1, registration_otp = NULL WHERE email = ?", (verification.email,))
            conn.commit()
            return {"message": "Email verified successfully. Your account is now active."}
        else:
            raise HTTPException(status_code=400, detail="Invalid OTP. Please try again or request a new OTP.")
    else:
        raise HTTPException(status_code=500, detail="Database connection error.")

@app.post("/login/")
def login(user: LoginUser):
    conn = create_connection("user_data.db")
    if conn is not None:
        cursor = conn.cursor()
        # Retrieve password, email_verified, failed_attempts, and last_attempt_time
        cursor.execute("SELECT password, email_verified, failed_attempts, last_attempt_time FROM users WHERE username = ?", (user.username,))
        user_record = cursor.fetchone()

        if user_record:
            stored_password, email_verified, failed_attempts, last_attempt_time = user_record
            
            # Check if the email is verified
            if not email_verified:
                raise HTTPException(status_code=403, detail="Please verify your email before logging in.")

            # Check if account is temporarily blocked
            if last_attempt_time and (datetime.now() - datetime.strptime(last_attempt_time, '%Y-%m-%d %H:%M:%S')) < timedelta(minutes=5) and failed_attempts >= 3:
                raise HTTPException(status_code=403, detail="Account locked due to multiple failed login attempts. Please try again later.")

            # Check password
            if hashlib.sha256(user.password.encode()).hexdigest() == stored_password:
                # Reset failed_attempts if login is successful
                cursor.execute("UPDATE users SET failed_attempts = 0, last_attempt_time = NULL WHERE username = ?", (user.username,))
                conn.commit()
                return {"message": "Login successful!"}
            else:
                # Update failed_attempts and last_attempt_time
                new_attempts = failed_attempts + 1
                cursor.execute("UPDATE users SET failed_attempts = ?, last_attempt_time = ? WHERE username = ?", (new_attempts, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user.username))
                conn.commit()
                raise HTTPException(status_code=401, detail="Incorrect username or password.")
        else:
            raise HTTPException(status_code=404, detail="User does not exist.")
    else:
        raise HTTPException(status_code=500, detail="Database connection error.")

@app.post("/forgot-password/")
def forgot_password(request: ForgotPasswordRequest):
    conn = create_connection("user_data.db")
    if conn is not None:
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE username = ?", (request.username,))
        record = cursor.fetchone()
        if record and record[0] == request.email:
            otp = send_otp_email(request.email)
            cursor.execute("UPDATE users SET reset_otp = ? WHERE username = ?", (otp, request.username))
            conn.commit()
            return {"message": "OTP sent to your email. Please check your email to reset your password."}
        else:
            raise HTTPException(status_code=404, detail="No matching user found for the provided username and email.")
    else:
        raise HTTPException(status_code=500, detail="Database connection error.")

@app.post("/reset-password/")
def reset_password(request: ResetPasswordRequest):
    conn = create_connection("user_data.db")
    if conn is not None:
        cursor = conn.cursor()
        # Retrieve current OTP and check if it's valid
        cursor.execute("SELECT reset_otp FROM users WHERE username = ?", (request.username,))
        record = cursor.fetchone()
        if record and str(record[0]) == str(request.otp):
            # Update the user's password and reset account lock status
            new_hashed_password = hashlib.sha256(request.new_password.encode()).hexdigest()
            cursor.execute("UPDATE users SET password = ?, reset_otp = NULL, failed_attempts = 0, last_attempt_time = NULL WHERE username = ?", (new_hashed_password, request.username))
            conn.commit()
            return {"message": "Your password has been reset successfully. You can now log in with your new password."}
        else:
            raise HTTPException(status_code=400, detail="Invalid OTP. Please try again.")
    else:
        raise HTTPException(status_code=500, detail="Database connection error.")


@app.delete("/delete/")
def api_delete_user(user: DeleteUserRequest):
    conn = create_connection("user_data.db")
    if conn is not None:
        cursor = conn.cursor()
        # Retrieve the stored password for verification
        cursor.execute("SELECT password FROM users WHERE username = ?", (user.username,))
        record = cursor.fetchone()

        if record:
            stored_password = record[0]
            # Check if the provided password matches the stored password
            if hashlib.sha256(user.password.encode()).hexdigest() == stored_password:
                # Proceed with deleting the user
                if delete_user(conn, user.username):
                    return {"message": "User deleted successfully."}
                else:
                    raise HTTPException(status_code=404, detail="No user found with that username.")
            else:
                raise HTTPException(status_code=401, detail="Incorrect password.")
        else:
            raise HTTPException(status_code=404, detail="No user found with that username.")
    else:
        raise HTTPException(status_code=500, detail="Database connection error.")

# Additional functions for database interactions, hashing, etc., go here

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
