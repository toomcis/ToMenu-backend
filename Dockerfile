FROM python:3.12.9-slim

# Install cron and other necessary packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy requirements.txt and install dependencies
COPY requirements.txt /app
RUN pip install --no-cache-dir -r requirements.txt

# Copy main.py, api.py, and start.sh to the container
COPY main.py api.py scrapeAll.sh start.sh ./

# Copy webUI and scrapers and other folders
COPY webUI ./webUI
COPY scrapers ./scrapers
COPY static ./static

# Expose the port that the application will run on
EXPOSE 8000

# Start the application
CMD ["./start.sh"]