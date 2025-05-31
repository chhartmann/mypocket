# Use Python 3.9 as base image
FROM python:3.9-alpine

# Set working directory in the container
WORKDIR /app


# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p static/images

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV SECRET_KEY=change-this-in-production
ENV JWT_SECRET_KEY=change-this-in-production

# Expose port
EXPOSE 5010

# Run the application
CMD ["flask", "run", "--host=0.0.0.0", "--port=5010"]
