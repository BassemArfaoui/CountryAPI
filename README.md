# CountryAPI

## Overview

CountryAPI is a comprehensive API that provides detailed information about any country in the world. The API offers various services, each with its own authentication requirements (No Auth/ Basic Auth / API Key / Bearer Token ) , ensuring secure access to the data.

## Features

- Retrieve detailed information about any country.
- Different services for various types of country data.
- Each service has its own authentication requirements for enhanced security.
- API Documentation : https://documenter.getpostman.com/view/36645222/2sA3kUGhjm
## Technologies Used

- **Backend**: Node.js, Express.js
- **Database**: PostgreSQL


## Setup and Installation

### Prerequisites

- Node.js
- PostgreSQL
-nodemon
### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/BassemArfaoui/CountryAPI.git
   cd CountryAPI
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Set up the PostgreSQL database:

   - Create a new PostgreSQL database.
   - use the scv to create the database.

4. Configure environment variables:

   Create a `.env` file in the root directory and add your environment variables:

   ```plaintext
   DB_user=postgres
   DB_host=localhost
   Db_name=//database name
   PG_password=//postgres password
   DB_port=5432

   ```

5. Run the application:

   ```bash
   node index.js
   ```

   Alternatively, you can use:

   ```bash
   nodemon index.js
   ```

   Or:

   ```bash
   npm run dev
   ```






## Documentation

For detailed documentation of the API, please refer to the [Postman Documentation](https://documenter.getpostman.com/view/36645222/2sA3kUGhjm).

