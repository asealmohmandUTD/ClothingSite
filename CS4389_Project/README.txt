**E-Commerce Website with Enhanced Security Features**

Description: This project is a Flask-based web application tailored for the e-commerce clothing market.
It focuses on user experience and incorporates advanced security measures, including two-factor authentication,
to ensure user data protection and secure transactions.

**Must use Python 3.9**

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

> IMPORTANT - 2FA login only works with authorzied users at the moment since we are implementing it with a free trail of MailGun.
    > I sent out emails to 'exc067000@utdallas.edu', 'jinghui.guo@utdallas.edu', and 'mxi170330@utdallas.edu'
    > emails will ask for a confirmation. Once accepted, 2FA authentication will be enabled for those emails.
    > Email Ubadah Saleh at 'ujs200000@utdallas.edu' for help regarding this topic.

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
> ALL EMAILS SENT WILL BE IN SPAM (authentication and order confirmation).
> A site.db file will be created at run in the instance folder. You can delete it to earse the DB.
> A virtual env might need to be created in order to get the program running.
> Due to a lack of team members, payment authorization and confirmation was not set up, but just a prototype for now.
