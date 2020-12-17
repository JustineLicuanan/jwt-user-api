# JWT User API

an elegant user API with JWT authentication made using Node, Express, MongoDB/Mongoose, and JWT

## Installation

Rename `.env.example` file to just `.env` then replace the environment variable values with your own values. Here's what's inside `.env.example` file:

```sh
# Rename this ".env.example" file to just ".env"
DB_URI=REPLACE_THIS_WITH_YOUR_MONGODB_URI
PORT=REPLACE_THIS_WITH_YOUR_DESIRED_PORT
JWT_SECRET=REPLACE_THIS_WITH_YOUR_DESIRED_JWT_SECRET

# Sample values for each variables above
# DB_URI=mongodb://127.0.0.1:27017/sample-mongo-uri
# PORT=3001
# JWT_SECRET=ultimateSecret
```

Install the dependencies

```bash
npm install
```

## Usage

Run the server

```bash
npm run dev
```

### `/users` Endpoints

```http
# Register endpoint
POST {{host}}/users/register
Content-Type: application/json

{
   "name": "",
   "email": "",
   "username": "",
   "password": ""
}

###

# Login endpoint
POST {{host}}/users/login
Content-Type: application/json

{
   "username": "",
   "password": ""
}

###

# Logout endpoint
GET {{host}}/users/logout

###

# View current logged in user token endpoint
GET {{host}}/users/profile

###

# View specific user profile endpoint
GET {{host}}/users/profile/{{username}}

###

# View all user profiles endpoint
GET {{host}}/users

###

# Update current logged in user profile endpoint
PATCH {{host}}/users/profile/update
Content-Type: application/json

{
   "name": "",
   "email": "",
   "username": ""
}

###

# Change current logged in user password endpoint
PATCH {{host}}/users/profile/update/password
Content-Type: application/json

{
   "password": ""
}

###

# Delete current logged in user endpoint
DELETE {{host}}/users/profile/delete
```

### `/admin` Endpoints

To access `/admin` endpoints, first you have to create an admin user. To create an admin user, do a `POST` request to `/users/register` with your desired `{ name, email, username, password }` attached in the body, then change the role of that user from `4` to `1` in your MongoDB database.

```http
# Create user endpoint
POST {{host}}/admin/create
Content-Type: application/json

{
   "role": 4,
   "name": "",
   "email": "",
   "username": "",
   "password": ""
}

###

# View specific user profile endpoint
GET {{host}}/admin/view/{{username}}

###

# View all user profiles endpoint
GET {{host}}/admin/view

###

# Update specific user profile endpoint
PATCH {{host}}/admin/update/{{username}}
Content-Type: application/json

{
   "role": 4,
   "name": "",
   "email": "",
   "username": ""
}

###

# Change specific user password endpoint
PATCH {{host}}/admin/update/password/{{username}}
Content-Type: application/json

{
   "password": ""
}

###

# Delete specific user endpoint
DELETE {{host}}/admin/delete/{{username}}
```

## Built With

- JavaScript - the programming language used.
- [Node](https://nodejs.org) - the runtime environment used to run JavaScript on the backend.
- [Express](https://expressjs.com) - the web framework used for Node.
- [MongoDB](https://www.mongodb.com) - the database used.
- [Mongoose](https://mongoosejs.com) - used for MongoDB object data modeling (ODM).
- [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) - used for authentication.
- [Dotenv](https://github.com/motdotla/dotenv) - used to store environment variables.
- [bcrypt.js](https://github.com/dcodeIO/bcrypt.js) - used to hash passwords.
- [validator.js](https://github.com/validatorjs/validator.js) - used for validation.
