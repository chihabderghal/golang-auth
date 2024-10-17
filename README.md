# Golang Auth Project

The Golang Auth project is a user authentication service built with [Go](https://go.dev/) using the Fiber framework.
It is designed to handle secure user registration, login, JWT-based authentication, image uploads,
and user profile management.

To begin working on the project you have an options for settings up development environment :

- **Using Docker for the development environment:** Docker provides a streamlined approach
  to
  setting up a consistent development environment. The project includes a Dockerfile and
  Docker Compose configuration, which define all necessary dependencies such as `Go`,
  `PostgreSQL`, and `Adminer` for database management. By using Docker, you avoid the need for
  manual installation of dependencies on your local machine. The provided configuration
  ensures that the correct versions of Go and PostgreSQL are used and that the entire
  environment is reproducible across different systems. Detailed instructions in the project
  documentation guide you through building and running the Docker environment, making it easy
  to start working on the project while ensuring consistency and isolation.

## Development Environment

### Docker

docker provides a convenient way to create and manage development environments using containers. To set up the
development environment using Docker configuration present in this project, follow these steps:

1. **Install Docker:** Docker is available for different operating systems. Visit the
   official [Docker website](https://www.docker.com/products/docker-desktop/) and download the
   appropriate version for your system. Follow the installation guide to your OS to install Docker.
2. **Install Docker Compose:** [Docker Compose](https://docs.docker.com/compose/) is included in Docker Desktop for
   Windows and macOS, but on Linux, it may
   need to be installed separately.
3. **Build Image:** To build Docker image for this project, you need to run the following command:
    ```bash
    docker compose build 
    ```
4. **Run Image:** You can run your Docker container using the following command:
    ```bash
    docker compose up
    ```
    - `Run Shell`: You can also access the container shell by running the following command:
   ```bash
    docker compose exec app /bin/sh
   ```

### Configuration

Before running the application with Docker, you need to set up your environment variables. You can do this by creating a
`.env` file from the provided example:

```bash
cp ./.env.example ./.env
```

The `.env` file will contain empty values that you need to fill in. Below is the structure of the `.env` file along with
descriptions for each variable:

```dotenv
# Port for the application
PORT=

# Database configuration
DB_HOST=              # Host for the database (e.g., localhost or an IP address)
DB_USER=              # Username for the database
DB_PASSWORD=          # Password for the database
DB_NAME=              # Name of the database
DB_PORT=              # Port for the database (default is usually 5432 for PostgreSQL)

# JWT Secret Keys
AT_SECRET=            # Secret key for Access Token (generate securely)
RT_SECRET=            # Secret key for Refresh Token (generate securely)

# Google OAuth Configuration (create one at: https://console.developers.google.com/apis/credentials)
GOOGLE_CLIENT_ID=     # Client ID for Google OAuth 
GOOGLE_CLIENT_SECRET= # Client Secret for Google OAuth 
GOOGLE_REDIRECT_URL=  # Redirect URL for Google OAuth

# Resend API Key (create one at: https://resend.com/)
RESEND_API_KEY=       # API Key for the Resend service 
```

Here’s an expanded explanation of your project structure, detailing what each component contains and its purpose:

---

## Running the App

If you're running the application without Docker, follow these steps:

1. **Configure your environment variables**: Make sure you have set up your `.env` file as described in the previous
   section.

2. **Start the application**: Use the following command to run the application:

   ```bash
   go run ./cmd/main.go
   ```

### Building the Application

To build the application into a binary executable, use the following command:

```bash
go build -o myapp ./cmd/main.go
```

- This command compiles the application and creates an executable named `main` in the root directory.
- You can replace `main` with any name you prefer for your executable.

### Running the Built Application

Once you have built the application, you can run it using:

```bash
./main
```
---

## Testing the App
To run the tests for the application, use the following command:
```bash
go test -v ./tests/...
```

## Project Structure

Here's a high-level overview of the project structure:

```plaintext
├── cmd                # Application entry point
├── config             # Configuration files
├── docker             # Docker-related configurations
├── internal           # Core application logic
├── pkg                # Utilities and helper functions
├── scripts            # Migration and seeder scripts
├── tests              # Test files
├── uploads            # Directory for user-uploaded files
└── README.md          # Project documentation
```

### Detailed Structure

- **`cmd`**:
    - Contains the application's main entry point (e.g., `main.go`).

- **`config`**:
    - Holds configuration files for database connections and environment settings.

- **`docker`**:
    - Includes Docker configurations such as the `Dockerfile` and `docker-compose.yml` for container orchestration.

- **`internal`**:
    - Contains core application logic organized into:
        - **`auth`**: Authentication logic (e.g., token generation).
        - **`controllers`**: Business logic for handling requests.
        - **`middlewares`**: Middleware functions for request processing.
        - **`routes`**: Definitions of API routes.

- **`pkg`**:
    - Houses utility functions and reusable components:
        - **`models`**: Data models (e.g., User).
        - **`utils`**: Helper functions (e.g., email sending, hashing).

- **`scripts`**:
    - Contains migration and seeder scripts for database management.

- **`tests`**:
    - Dedicated to unit and integration tests, organized by feature.

---


### Endpoints

- **Auth Endpoints**

| Method | Endpoint                               | Description                           |
|--------|----------------------------------------|---------------------------------------|
| POST   | `/api/auth/register`                   | Registers a new user                  |
| POST   | `/api/auth/login`                      | Logs in a user and returns JWT tokens |
| GET    | `/api/auth/request-email-verification` | Sends a verification email            |
| GET    | `/api/auth/verify`                     | Verifies the user's email             |
| POST   | `/api/auth/forget-password`            | Initiates the password reset process  |
| POST   | `/api/auth/reset-password`             | Resets the user's password            |

- **User Endpoints**

| Method | Endpoint                     | Description                                |
|--------|------------------------------|--------------------------------------------|
| GET    | `/api/users/profile`         | Retrieves the authenticated user's profile |
| PUT    | `/api/users/update-user`     | Updates user profile information           |
| DELETE | `/api/users/delete-user`     | Deletes the authenticated user's account   |
| GET    | `/api/users/get-admin-users` | Retrieves a list of all users (admin only) |

- Providers Endpoints

| Method | Endpoint                 | Description                                                             |
|--------|--------------------------|-------------------------------------------------------------------------|
| GET    | `/api/auth/google/login` | Retrieves the profile information of the user authenticated via Google. |

---