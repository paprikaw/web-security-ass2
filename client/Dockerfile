# Use an official Python runtime as a parent image
FROM python:3.8-slim-buster

# Set the working directory inside the container
WORKDIR /app

# Copy the client.py file to the container
COPY client.py /app

# Install the required packages
RUN pip install requests

# Run client.py when the container launches
CMD ["python", "client.py"]
