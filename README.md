# MyPocket

MyPocket is a self-hosted bookmark manager built with Flask. It allows you to save, organize, and manage your bookmarks with features like tagging, notes, and image attachments.

## Features

- Save URLs with titles, summaries, and notes
- Automatic title fetching from webpages
- Tag-based organization
- Image attachment support
- User authentication and API access
- CSV import functionality
- Responsive tile and list views
- REST API with JWT authentication

## Requirements

- Python 3.x
- Flask
- SQLite
- Additional requirements listed in `requirements.txt`

## Installation

1. Clone the repository:
```bash
git clone https://github.com/YourUsername/mypocket.git
cd mypocket
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
flask run
```
This will create the database and a default user (username: 'user', password: 'password')

5. Start the application:
```bash
flask run --port=5080
```

The application will be available at `http://localhost:5080`

## Docker Support

You can also run the application using Docker:

```bash
docker build -t mypocket .
docker run -p 5080:5080 mypocket
```

## API Usage

The application provides a REST API with JWT authentication. To get an access token:

```bash
curl -X POST http://localhost:5080/api/token \
  -H "Content-Type: application/json" \
  -d '{"username":"your_username","password":"your_password"}'
```

Use the token in subsequent requests:

```bash
curl http://localhost:5080/api/urls \
  -H "Authorization: Bearer your_access_token"
```

## Security Notes

- Change the default user credentials after first login
- In production, set proper `SECRET_KEY` and `JWT_SECRET_KEY` environment variables
- Configure proper CORS settings if needed
- Use HTTPS in production

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
