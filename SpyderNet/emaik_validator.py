import re
import dns.resolver
import smtplib
import ssl
import secrets
import string
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configuration (These should be stored securely, e.g., in environment variables or a config file)
EMAIL_HOST = 'smtp.gmail.com'  # e.g., 'smtp.gmail.com', 'smtp.office365.com'
EMAIL_PORT = 587  # Or 465 for SSL
EMAIL_USER = 'your_email@gmail.com'  # Your email address
EMAIL_PASSWORD = 'your_email_password'  # Your email password or application-specific password
BASE_URL = 'http://your-website.com'  # Your website's base URL (for confirmation link)
CONFIRMATION_TOKEN_EXPIRATION_HOURS = 24  # Token expiration time

def is_valid_email_syntax(email):
    """Checks if an email address has a valid syntax using a regex."""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.fullmatch(pattern, email) is not None

def is_valid_email_domain(email):
    """Checks if the domain of an email address has a valid MX record."""
    try:
        domain = email.split('@')[1]
        records = dns.resolver.resolve(domain, 'MX')
        return len(records) > 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return False
    except Exception as e:
        print(f"Error during domain check: {e}")
        return False

def generate_confirmation_token():
    """Generates a random, secure confirmation token."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for i in range(32))  # Generate a 32 character token

def send_confirmation_email(email, token):
    """Sends a confirmation email to the user."""
    subject = 'Confirm Your Email Address'
    confirmation_link = f'{BASE_URL}/confirm?email={email}&token={token}'  # Include email in the link
    body = f"""
    Please click the following link to confirm your email address:
    {confirmation_link}
    This link will expire in {CONFIRMATION_TOKEN_EXPIRATION_HOURS} hours.
    """
    # Create message
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    context = ssl.create_default_context()
    try:
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls(context=context)  # Use STARTTLS for security
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_USER, email, msg.as_string())
        server.quit()
        print(f"Confirmation email sent to {email}")
        return True
    except Exception as e:
        print(f"Error sending confirmation email: {e}")
        return False

def store_token(email, token):
    """
    Stores the email and its associated token in a dictionary.
    In a real application, this would be stored in a database with an expiration timestamp.
    """
    #  Important:  In a real application, use a database (e.g., PostgreSQL, MySQL)
    #  to store the token, email, and an expiration timestamp.  This dictionary
    #  is only for demonstration purposes and will lose data if the script restarts.
    global token_storage
    expiration_time = datetime.datetime.now() + datetime.timedelta(hours=CONFIRMATION_TOKEN_EXPIRATION_HOURS)
    token_storage[email] = {'token': token, 'expiration': expiration_time}

def get_stored_token(email):
    """
     Retrieves the stored token and its expiration for a given email from the dictionary.
     In a real application, this would be retrieved from a database.
    """
    global token_storage
    if email in token_storage:
        return token_storage[email]['token'], token_storage[email]['expiration']
    else:
        return None, None

def validate_confirmation_token(email, token):
    """
    Validates the confirmation token.
    In a real application, this would check against a database and also ensure the token hasn't expired.
    """
    stored_token, expiration = get_stored_token(email)
    if stored_token and stored_token == token and expiration > datetime.datetime.now():
        return True
    else:
        return False

def main():
    """
    Main function to demonstrate email validation and confirmation.
    """
    email_address = input("Enter the email address to validate: ")

    # 1. Syntax Check
    if not is_valid_email_syntax(email_address):
        print("Invalid email address syntax.")
        return

    # 2. Domain Check
    if not is_valid_email_domain(email_address):
        print("Invalid email address domain.")
        return

    # 3.  Check for existing confirmation (optional, but recommended)
    # In a real system, you'd check your database to see if this email is already confirmed.
    # If it is, you might just log the user in or display a message.  For this example, we'll skip it.

    # 4. Generate and Store Token
    token = generate_confirmation_token()
    store_token(email_address, token)  # Store in "database" (in memory dict for this example)

    # 5. Send Confirmation Email
    if send_confirmation_email(email_address, token):
        print(f"Confirmation email sent to {email_address}. Please check your inbox.")
    else:
        print("Failed to send confirmation email.  Email address not validated.")
        return  #  Important:  Consider what to do here.  You might want to allow the user to try again.

    #  6.  In a real application, this part would be handled by a separate web endpoint
    #  that the user is redirected to after clicking the confirmation link.
    #  For this example, we'll simulate the user clicking the link:
    user_token_input = input("Enter the confirmation token from the email (or 'test' to simulate valid token): ")
    if user_token_input == 'test':
        user_token_input = token #  For testing
    if validate_confirmation_token(email_address, user_token_input):
        print("Email address confirmed successfully!")
        #  In a real application, you would:
        #  - Mark the email address as confirmed in your database.
        #  - Log the user in, or redirect them to the next step in your application.
        #  - Delete the used token from the database.
    else:
        print("Invalid or expired confirmation token.  Email address not confirmed.")
        #  In a real application, you might:
        #  -  Allow the user to request a new confirmation email.
        #  -  Provide an error message with instructions.

#  This dictionary is serving as a placeholder for a database for this example.
#  In a real application, you would use a proper database.
token_storage = {}

if __name__ == "__main__":
    main()
