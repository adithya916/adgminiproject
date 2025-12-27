# Secure User Management System

Hi there! 👋 Welcome to the **Secure User Management System**.

This project is a prototype I built to demonstrate how to handle user authentication securely using Node.js, Express, and MongoDB. It's not just a basic login form; I've baked in several security best practices to protect against common web attacks like XSS, CSRF, and SQL/NoSQL injection.

If you're looking to understand how secure sessions work "under the hood" without relying on heavy frameworks like NextAuth or Passport, this is a great reference.

## 🚀 Key Features

*   **Secure Authentication**: A complete flow for Registering, Logging in, and Logging out.
*   **Session Management**: I'm using **HTTP-only cookies** to store session IDs. This means client-side JavaScript (and potential attackers) can't read them.
*   **Defense in Depth**:
    *   **BCrypt**: Passwords are salted and hashed. Even I can't see your password.
    *   **CSRF Protection**: Prevents bad sites from making requests on your behalf.
    *   **Rate Limiting**: Stops brute-force attacks by limiting login attempts.
    *   **Helmet**: Sets HTTP headers to make the browser behavior more secure.
    *   **Input Validation**: Checks all incoming data to ensure it's safe and expected.

## 🛠️ Tech Stack

*   **Backend**: Node.js & Express (The engine)
*   **Database**: MongoDB with Mongoose (Flexible data storage)
*   **Frontend**: Plain HTML, CSS, and Vanilla JavaScript (Kept it simple to focus on logic)

## 📂 Project Structure

Here is a quick map to help you navigate the code:

```
.
├── backend
│   ├── src
│   │   ├── config          # DB connection logic
│   │   ├── controllers     # The "brain" of the app (handles requests)
│   │   ├── models          # Data blueprints (User & Session schemas)
│   │   ├── middleware      # Security guards (Auth checks, Rate limits)
│   │   ├── routes          # API URL definitions
│   │   ├── utils           # Helpers like validation
│   │   └── server.js       # Where it all starts
│   └── package.json
├── frontend
│   ├── public              # The visible part (HTML)
│   └── src                 # The logic part (JS & CSS)
└── README.md
```

## 🏃‍♂️ How to Run It

### Prerequisites
You'll need **Node.js** installed. You also need **MongoDB** running on your machine (or a connection string to a cloud instance).

### Step-by-Step

1.  **Get the Backend Ready**
    ```bash
    cd backend
    npm install
    ```

2.  **Configure the Environment**
    Create a file named `.env` inside the `backend` folder. You can copy the example:
    ```bash
    # Update the MONGO_URI if your database isn't on localhost
    cp .env.example .env
    ```

3.  **Start the Engine**
    ```bash
    npm start
    # Pro tip: Use 'npm run dev' if you want it to restart when you edit files.
    ```

4.  **View the App**
    Open your browser and go to: `http://localhost:3000`

## 🔐 Security Deep Dive

Here is a bit more detail on the security decisions I made:

### Why HTTP-Only Cookies?
Storing tokens in `localStorage` is common but risky because any script on your page (even a rogue 3rd party library) can read them. By using `HttpOnly` cookies, the browser handles the storage and sending of the token, keeping it invisible to JavaScript.

### CSRF (Cross-Site Request Forgery)
Since we use cookies, we are vulnerable to CSRF. To fix this, I implemented the "Double Submit Cookie" pattern. The server gives the frontend a token, and the frontend must send that token back in a header for every write request. If they don't match, the server rejects the request.

### NoSQL Injection
Even though we aren't using SQL, hackers can still trick databases. I use Mongoose's schema validation and sanitation libraries to make sure a password field is actually a string, not a malicious query object.

## 📝 API Endpoints

*   `POST /api/auth/register` - Create a new account
*   `POST /api/auth/login` - Sign in
*   `POST /api/auth/logout` - Sign out
*   `GET /api/users/me` - Check who is currently logged in

---
*Built with ❤️ and ☕.*
