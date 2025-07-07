# Blockauth

[//]: # ([![PyPI version]&#40;https://badge.fury.io/py/block-inter-auth.svg&#41;]&#40;https://badge.fury.io/py/block-inter-auth&#41;)
[//]: # ([![PyPI - Python Version]&#40;https://img.shields.io/pypi/pyversions/block-inter-auth&#41;]&#40;https://pypi.org/project/block-inter-auth/&#41;)

Blockauth is an authentication package for Python REST APIs, designed for internal use. It provides JWT-based authentication mechanisms, including login and token refresh functionalities. It also supports Social login using OAuth2.

_Disclaimer: This package is currently at initiative state so you can expect frequent changes based on the teams requirements._

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration Setup](#configuration-Setup)
  - [Django Configs](#django-configs)
  - [BlockAuth Configs](#blockauth-configs)
  - [Spectacular(API documentation) Configs](#spectacularapi-documentation-configs)
  - [Inherit Blockauth User Model](#inherit-blockauth-user-model)
  - [Add URLs](#add-urls)
- [User journey of some functionalities](#user-journey-of-some-functionalities)
  - [Sign up](#sign-up)
  - [Basic Login](#basic-login)
  - [Passwordless Login](#passwordless-login)
  - [Token Refresh](#token-refresh)
  - [Password Reset](#password-reset)
  - [Change Email](#change-email)
- [Social Providers Login Mechanism (Google, LinkedIn, Facebook, etc.)](#social-providers-login-mechanism-google-linkedin-facebook-etc)
- [Utility Classes](#utility-classes)
  - [Communication Class](#communication-class)
  - [Trigger Classes](#trigger-classes)
- [Logging in BlocAuth](#logging-in-blocauth)
  - [Supported Log Levels and Icons](#supported-log-levels-and-icons)
  - [Custom Logger Integration](#custom-logger-integration)
  - [Example: Custom Logger Class](#example-custom-logger-class)
  - [Django Settings Configuration](#django-settings-configuration)
- [Rate Limiting](#rate-limiting)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Features

- JWT Authentication
- Token refresh functionality
- SignUp with email and password
- Login with email and password (Basic Auth)
- Login via OTP (Passwordless login)
- Reset password
- Change password
- Change email
- Google, Facebook, LinkedIn login (OAuth2)


## Requirements

- python = ^3.12
- django = 5.1.4
- pyjwt = 2.9.0
- requests = 2.32.3
- djangorestframework = 3.15.2
- setuptools = ^75.6.0
- drf-spectacular = 0.28.0
- drf-spectacular-sidecar = 2025.7.1

## Installation

#### Direct Installation
To install the package, we prefer poetry. It's recommended to install the package in a virtual environment. Also make sure to add ssh to your github account.
With Poetry add dependency like below in `pyproject.toml` file:
```
[tool.poetry.dependencies]
...
blockauth = { git = "git@github.com:BloclabsHQ/auth-pack.git", branch = "dev" }  # <---- give your prefered branch
...
```
Then run the command
`poetry update`


#### Editable Mode
To install the package in **editable mode**, you can clone the repository and install it in the virtual environment.
After activating python virtual environment, go to the folder where the current repository should be  
located and then follow the below commands:

```sh
git clone <repo-url>
pip install -e <path-to-repo>
```

`pip install -e` is used to install a Python package in "editable" or "development"
mode. This is helpful when you are actively developing a package and want the 
changes made to the source code to be reflected immediately without needing to 
reinstall the package each time.


## Configuration Setup

### Django Configs
Add the package to your Django project's `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    ...
    'rest_framework',
    'blockauth',
    ...
]
```

Add the Blockauth authentication classe to your Django project's `REST_FRAMEWORK` settings.
By this way, the package's authentication classes will be used for the APIs.:

```python
REST_FRAMEWORK = {
    ...
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'blockauth.authentication.JWTAuthentication',
    ),
    ...
}
```


### BlockAuth Configs
Configs which can be added to the Django project's `settings.py`. 
If you don't add these configs, the default values will be used which are shown here:

- _**AUTH_PROVIDERS** has no default values, you need to add the values for the providers you want to use. 
If you do not add them then the social auth URLs related to the providers won't be available.
See the following [Video tutorials](#social-providers-login-mechanism-google-linkedin-facebook-etc) to create OAuth client id & client secret._
- _**DEFAULT_TRIGGER_CLASSES** has default classes implemented within blockauth package. It's recommended to implement
own class and add the class path in the settings. Details disccussed in the [Utility Classes](#utility-classes) section._ 
- _**DEFAULT_NOTIFICATION_CLASS** has default class implemented within blockauth package. It's recommended to implement
own class and add the class path in the settings. Details disccussed in the [Utility Classes](#utility-classes) section._

```python
BLOCK_AUTH_SETTINGS = {
    "BLOCK_AUTH_USER_MODEL": "{{app_name.model_class_name}}",  # replace it with your custom user model class name for Blockauth users
    "CLIENT_APP_URL": "http://localhost:3000", # this is the URL of the client app which will communicate with the backend API
    
    "ACCESS_TOKEN_LIFETIME": timedelta(seconds=3600),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "ALGORITHM": "HS256",
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",   # Field name in the user model which will be used as user id in the JWT token
    
    "OTP_VALIDITY": timedelta(minutes=3),
    "OTP_LENGTH": 6,
    "REQUEST_LIMIT": (3, 30),  # (number of request, duration in second) rate limits based on per (identifier, subject, and IP address)
        
    "AUTH_PROVIDERS": {
        "GOOGLE": {
            "CLIENT_ID": os.getenv('GOOGLE_CLIENT_ID'),
            "CLIENT_SECRET": os.getenv('GOOGLE_CLIENT_SECRET'),
            "REDIRECT_URI": os.getenv('GOOGLE_REDIRECT_URI'),
        },
        "LINKEDIN": {
            "CLIENT_ID": os.getenv('LINKEDIN_CLIENT_ID'),
            "CLIENT_SECRET": os.getenv('LINKEDIN_CLIENT_SECRET'),
            "REDIRECT_URI": os.getenv('LINKEDIN_REDIRECT_URI'),
        },
        "FACEBOOK": {
            "CLIENT_ID": os.getenv('FACEBOOK_CLIENT_ID'),
            "CLIENT_SECRET": os.getenv('FACEBOOK_CLIENT_SECRET'),
            "REDIRECT_URI": os.getenv('FACEBOOK_REDIRECT_URI'),
        }
    },
    
    # don't need to add DEFAULT_TRIGGER_CLASSES & DEFAULT_NOTIFICATION_CLASS object if you want to use default classes
    "DEFAULT_TRIGGER_CLASSES": {
        "POST_SIGNUP_TRIGGER": '{{path.to.your.Class}}',  # replace it with your own class path
        "PRE_SIGNUP_TRIGGER": '{{path.to.your.Class}}',   # replace it with your own class path
        "POST_LOGIN_TRIGGER": '{{path.to.your.Class}}',   # replace it with your own class path
    },
    
    "DEFAULT_NOTIFICATION_CLASS": "{{path.to.your.Class}}",   # replace it with your own class path
    "BLOCK_AUTH_LOGGER_CLASS": '{{path.to.your.Class}}',   # replace it with your own class path
}
```

### Spectacular(API documentation) Configs

Add the following related things to the Django project's `settings.py`:

```python
INSTALLED_APPS = [
    ...
    'drf_spectacular',
    'drf_spectacular_sidecar',
    ...
]

REST_FRAMEWORK = {
    ...
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema', 
    ...
}

# read more about the settings here: https://drf-spectacular.readthedocs.io/en/latest/readme.html#installation
SPECTACULAR_SETTINGS = {
    'TITLE': 'Your API Title',
    'DESCRIPTION': 'Your API description here',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'SWAGGER_UI_SETTINGS': {
        'deepLinking': True,
    },
}
```

Add the following URL pattern to the Django project's `urls.py`:

```python
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

urlpatterns += [
    # Schema generation endpoint
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    # Optional UI endpoints
    path('api/swagger/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]
```

After adding the above URL pattern, you can access the swagger documentation by going to the URL `http://localhost:8000/api/swagger/` or
the redoc documentation by going to the URL `http://localhost:8000/api/redoc/`.


### Inherit Blockauth User Model

Inherit the `blockauth.models.BlockUser` model in your custom User model in django project. An example is shown below:

```python
from django.db import models
from blockauth.models.user import BlockUser

class CustomUser(BlockUser):
    first_name = models.CharField("First name", max_length=50, null=True, blank=True)
    last_name = models.CharField("Last name", max_length=50, null=True, blank=True)
    date_joined = models.DateTimeField("date of joining", auto_now_add=True)
    is_online = models.BooleanField(default=False)

    # Profile Fields
    date_of_birth = models.DateField("date of birth", blank=True, null=True)
    bio = models.TextField("bio", blank=True, null=True, max_length=500)


    class Meta:
        db_table = "user"
```

Set this customer user model as the default user model in the Django project's `settings.py`:
```python
AUTH_USER_MODEL = 'app_name.CustomUser'
```

Make migration related commands in console to reflect database tables related to the app.
```shell
python manage.py makemigrations
python manage.py migrate
```

### Add URLs

Add the package's URLs to your Django project's `urls.py`:

```python
from django.urls import path, include

urlpatterns = [
    ...
    path('api/auth/', include('blockauth.urls')),
    ...
]
```
The available URLs will be shown in swagger after adding the above URL pattern:

Basic Auth:
- `auth/signup`: Request an OTP for signup with email & password.
- `auth/signup/otp/resend`: Resend OTP for signup with email.
- `auth/signup/confirm`:  Confirm sign up with email and otp.


- `auth/login/basic`: Login with **email** and **password** and get access token, refresh token.
- `auth/login/passwordless`: Request OTP for passwordless login with email.
- `auth/login/passwordless/confirm`: Confirm login with email and otp.
- `auth/token/refresh`: Refresh access token.


- `auth/password/reset`: Request OTP for password reset with email.
- `auth/password/reset/confirm`: Confirm password reset with email, otp and new password.
- `auth/password/change`: Change password with old password and new password while being an authenticated user


- `auth/email/change`: Request OTP for email change with current email and current password.
- `auth/email/change/confirm`: Confirm email change with current email, new email and otp.

Providers:
- `auth/google`: Redirect URL to Google login page.
- `auth/google/callback`: Callback URL after succesfull Google login. **This URL should be added to the Google OAuth2 client configuration**.


- `auth/linkedin`: Redirect URL to LinkedIn login page.
- `auth/linkedin/callback`: Callback URL to LinkedIn login page. **This URL should be added to the LinkedIn OAuth2 client configuration**.


- `auth/facebook`: Redirect URL to Facebook login page.
- `auth/facebook/callback`: Callback URL to Facebook login page. **This URL should be added to the Facebook OAuth2 client configuration**.

## User journey of some functionalities

### Sign up
1. The user requests to `auth/signup` with email and password. It will do the following:
   - Validate the email and password. Also checks whether the email is already registered or not.
   - Calls the `PRE_SIGNUP_TRIGGER` class with validated data to perform any pre-signup actions. _(This class should be implemented in the project. Currently, a dummy class is used by default.)_
   - Generates an OTP.
   - Calls the `DEFAULT_NOTIFICATION_CLASS` class with OTP information to send the OTP to the user. _(This class should be implemented in the project. Currently, a dummy class is used by default.)_
   - User created with email & password and `is_verified=False` by default.
2. The user confirms the signup by calling `auth/signup/confirm` with email and OTP. It will do the following:
   - Validate the OTP and email.
   - Updates the user attribute `is_verified=True`.
   - Calls the `POST_SIGNUP_TRIGGER` class with user information to perform any post-signup actions. _(This class should be implemented in the project. Currently, a dummy class is used by default.)_
3. In case if the user wants to resend the OTP, the user can call `auth/signup/otp/resend` with email.

### Basic Login
The user can log in with email and password. After successful login, the user will get an `access token` and a `refresh token`.
Token validity can be configured in the settings.

### Passwordless Login
1. The user requests to `auth/login/passwordless` with email. It will do the following:
   - Validate the email.
   - Generates an OTP.
   - Calls the `DEFAULT_NOTIFICATION_CLASS` class with OTP information to send the OTP to the user.
2. The user confirms the login by calling `auth/login/passwordless/confirm` with email and OTP. It will do the following:
   - Validate the OTP and email.
   - If the user is not found in the database, a new user is created with the email only and `is_verified=True`. Then calls the `POST_SIGNUP_TRIGGER` class with user information to perform any post-signup actions.
   - Calls the `POST_LOGIN_TRIGGER` class with user information to perform any post-login actions. _(This class should be implemented in the project. Currently, a dummy class is used by default.)_
   - Returns an `access token` and a `refresh token`.

### Token Refresh
The user can refresh the access token with the refresh token. The refresh token is used to generate a new access token.
Token validity can be configured in the settings.

### Password Reset
1. The user requests to `auth/password/reset` with email. It will do the following:
   - Validate the email.
   - Generates an OTP.
   - Calls the `DEFAULT_NOTIFICATION_CLASS` class with OTP information to send the OTP to the user.
2. The user confirms the password reset by calling `auth/password/reset/confirm` with email, OTP, and new password. It will do the following:
   - Validate the OTP, email and new password.
   - Update the user password with the new password.


### Change Email
1. The user requests to `auth/email/change` with current email and password. It will do the following:
   - Validate the current email and password.
   - Generates an OTP.
   - Calls the `DEFAULT_NOTIFICATION_CLASS` class with OTP information to send the OTP to the user.
2. The user confirms the email change by calling `auth/email/change/confirm` with current email, new email, and OTP. It will do the following:
   - Validate the current email, new email, and OTP.
   - Update the user email with the new email.

## Social Providers Login Mechanism (Google, LinkedIn, Facebook, etc.)

First, create OAuth client configurations for the social providers (Google, LinkedIn, Facebook, etc.) and add the **client id** 
and **client secret** to the **settings**. Also set the **redirect URL** to the callback URL of the respective provider.
Use the same **redirect URL** in the **auth providers** configuration.

#### Video tutorial for creating OAuth client
- [How to create Google OAuth client](https://www.youtube.com/watch?v=OKMgyF5ezFs&ab_channel=LearnWithDexter)
- [How to create Facebook OAuth client](https://youtu.be/LLlpH3vZVkg?t=133)
- [How to create LinkedIn OAuth client](https://www.youtube.com/watch?v=aV8d09e8nnA&ab_channel=LearnwithNAK)

#### Login Flow
1. Call the URL `auth/{provider_name}` to redirect to the respective provider login page.
2. The user will provide the credentials on the provider's login page & authorize the app.
3. Upon successful login, the user will be redirected to the `REDIRECT_URI` with the code. 
Here, `REDIRECT_URI` should redirect to the developer's frontend app.
4. The frontend app will call the backend API `auth/{provider_name}/callback?code={code}` with the code in query params.

#### What happens inside `auth/{provider_name}/callback` API?
1. By following the Oauth2 flow, user data (email, name, etc.) is fetched from the provider.
2. The user is then searched in the database via **email** field provided by the social provider. 
If the user is not found in the db, a new user is created with the `email`, `first_name` and `is_verified=True`.
Then calls the `POST_SIGNUP_TRIGGER` class with **provider name, user data from backend & provider** to perform any post-signup actions.
3. Calls the `POST_LOGIN_TRIGGER` class with **provider name, user data from backend & provider** to perform any post-login actions.
4. Finally, **access token and refresh token** generated with **user id** is returned.

## Utility Classes
### Communication Class
This class is used to send message to the user. The default class is `blockauth.utils.communication.DummyNotification`. 
Which is a dummy class and prints the message to the console. 

Developers have to implement their own class by inheriting the `blockauth.utils.communication.BaseCommunicationClass` and set the path in the settings.
Otherwise, the default class will be used.

Currently, the communication class is integrated in the following APIs:
- `auth/signup`: To send OTP for signup.
- `auth/signup/otp/resend`: To resend OTP for signup.
- `auth/login/passwordless`: To send OTP for passwordless login.
- `auth/password/reset`: To send OTP for password reset.
- `auth/password/change`: To send password change notification.
- `auth/email/change`: To send OTP for email change.

**Usage example**

```python
from blockauth.notification import BaseNotification


class CustomCommunication(BaseNotification):
    def communicate(self, purpose: str, context: dict) -> None:
        """
       :param purpose: should be used to identify the purpose of the communication.
       :param context: should contain the necessary information to send the message by developers own logic.
       """
        if purpose == 'otp_request':
            self.send_otp(context)
        elif purpose == 'password_change':
            self.send_password_change_email(context)

    def send_otp(self, context: dict) -> None:
        email = context.get('email')
        otp = context.get('otp')
        print(f"Sending OTP {otp} to email {email}")

    def send_password_change_email(self, context: dict) -> None:
        email = context.get('email')
        print(f"Sending password change notification to email {email}")
```

Currently, the following **purposes** are available for communication in the package. In the future, more purposes might be added:
```python
class CommunicationPurpose:
    OTP_REQUEST = "otp_request"
    PASSWORD_CHANGE = "password_change"
```

### Trigger Classes
These classes are used to perform some actions before and after the signup and login process.
- `PreSignupTrigger`: This class is called before the signup process. The default class is `blockauth.utils.triggers.DefaultPreSignupTrigger` which is a dummy class.
- `PostSignupTrigger`: This class is called after the signup process. The default class is `blockauth.utils.triggers.DefaultPostSignupTrigger` which is a dummy class.
- `PostLoginTrigger`: This class is called after the login process. The default class is `blockauth.utils.triggers.DefaultPostLoginTrigger` which is a dummy class.

Developers have to implement their own classes by inheriting the respective base classes and set the path in the settings.

**Usage example**
```python
from blockauth.triggers import BaseTrigger

class CustomPreSignupTrigger(BaseTrigger):
    def trigger(self, context: dict) -> None:
        # Custom logic before signup
        print(f"Custom pre-signup logic with context: {context}")

class CustomPostSignupTrigger(BaseTrigger):
    def trigger(self, context: dict) -> None:
        # Custom logic after signup
        print(f"Custom post-signup logic with context: {context}")

class CustomPostLoginTrigger(BaseTrigger):
    def trigger(self, context: dict) -> None:
        # Custom logic after login
        print(f"Custom post-login logic with context: {context}")
```

## Logging in BlocAuth

BlocAuth provides a unified logging interface for all authentication-related events. This logger supports multiple log levels, each with a unique icon for easy identification.

### Supported Log Levels and Icons

| Level      | Icon  | Description                                                        |
|------------|-------|--------------------------------------------------------------------|
| debug      | 🐞    | Detailed information for debugging                                 |
| info       | ℹ️    | General information about application events                       |
| warning    | ⚠️    | Unusual or unexpected events, not necessarily errors               |
| error      | ❌    | Errors that prevent normal execution                               |
| critical   | 🔥    | Very serious errors requiring immediate attention                  |
| exception  | 💥    | Exceptions, typically with stack traces                            |
| trace      | 🔍    | Fine-grained tracing information                                   |
| notice     | 📢    | Important but normal events requiring special attention            |
| alert      | 🚨    | Events requiring immediate action, not yet critical                |
| fatal      | ☠️    | Fatal errors leading to shutdown or unrecoverable failure          |
| success    | ✅    | Successful completion of an operation                              |
| pending    | ⏳    | Operations in progress or waiting for completion                   |

### Custom Logger Integration

To use your own logging backend, implement a callback class and set it in your Django settings inside the `BLOCK_AUTH_SETTINGS` dictionary as `BLOCK_AUTH_LOGGER_CLASS`.

#### Example: Custom Logger Class

```python
# myapp/logging.py
class MyBlockAuthLogger:
    def log(self, message, data=None, level="info", icon=None):
        # You can integrate with Python's logging, send to a service, or print
        print(f"{icon} [{level.upper()}] {message} | {data}")
```

#### Django Settings Configuration

```python
# settings.py
BLOCK_AUTH_SETTINGS = {
    "BLOCK_AUTH_LOGGER_CLASS": "myapp.logging.MyBlockAuthLogger",
    # ... other BlocAuth settings ...
}
```

- The logger class must implement a `log(message, data, level, icon)` method.
- The `icon` argument is a unicode symbol representing the log level.
- If `BLOCK_AUTH_LOGGER_CLASS` is not set in `BLOCK_AUTH_SETTINGS`, logging calls will be no-ops.


### Log Context Sanitization

To protect sensitive user data, BlocAuth automatically removes sensitive fields (such as passwords, tokens, codes, etc.) from all log data before writing to logs.

By default, the following fields are removed: `password`, `new_password`, `refresh`, `access`, `token`, `code`. This list can be extended by maintainers if needed.

All BlocAuth logging calls use this utility to ensure no sensitive information is ever logged.

## Rate Limiting
Rate limiting is implemented for requests currently. The rate limit is based on the number of requests and the duration.
The rate limit can be configured in the settings.

## License
All rights reserved. 

## Acknowledgments
- [Django](https://www.djangoproject.com/)
- [Django REST framework](https://www.django-rest-framework.org/)
- [PyJWT](https://pyjwt.readthedocs.io/en/stable/)
- [drf-yasg](https://drf-yasg.readthedocs.io/en/stable/)
- [Google OAuth2](https://developers.google.com/identity/protocols/oauth2)
- [LinkedIn OAuth2](https://docs.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow?context=linkedin/context)
- [Facebook OAuth2](https://developers.facebook.com/docs/facebook-login/)

