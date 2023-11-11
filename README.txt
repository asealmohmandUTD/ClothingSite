**E-Commerce Website with Enhanced Security Features**

Description: This project is a Flask-based web application tailored for the e-commerce clothing market.
It focuses on user experience and incorporates advanced security measures, including two-factor authentication,
to ensure user data protection and secure transactions.

*Features*
> User authentication and registration system.
> Two-factor authentication (2FA) via email.
> Secure password handling with bcrypt.
> SQLAlchemy for database management.
> Flask-Mail for email operations.

*Installation*
> Install required packages: pip3 install -r requirements.txt.
> Set up environment variables in .env file for database, mail server, and Flask secret key.

*Usage*
> Run the application: python app.py.
> Navigate to 127.0.0.1:5000 in a web browser.
> Use the signup feature to create a new user.
> Log in and explore the functionalities.

*Security Implementations*
> Bcrypt for hashing user passwords.
> Email-based 2FA for enhanced login security.
> Flask-WTF for form validation to prevent CSRF attacks.
> Secure configuration management using environment variables.

*Database Models*
> User: Stores user credentials and information.
> Token: Manages 2FA tokens and their expiration.
> ClothingItem: Details of clothing items available.
> Cart: Manages shopping cart items for each user.

*Notes*
> A site.db file will be created at run in the instance folder. You can delete it to earse the DB.
> A virtual env might need to be created in order to get the program running.