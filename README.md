# YARA-Scanner with Nginx Load Balancing and Docker

The YARA-Scanner application is a web-based tool that allows you to scan uploaded files against YARA rules to detect specific patterns or signatures in the files. We'll set up Nginx as a reverse proxy and load balancer to distribute incoming requests among multiple instances of the YARA-Scanner application.

## Prerequisites

Before you start, ensure you have the following installed on your system:

- Docker
- Docker Compose
- Nginx

## Getting Started

1. Clone the repository:

```bash
   git clone https://github.com/tcakmak0/yara-scan-api.git
   cd yara-scan-api
```

2. Specify the directory of YARA-Rules for bind mount. Go to 'docker-compose.yml' and change volume part of every instance of the scanner service accordingly

```docker-compose
    scanner_3:

    volumes:
      - YOUR/PATH/FOR/RULES:/yara-app/static/yara-rules
```

2. Build the Docker image:

```bash
    docker-compose build
```

3. Start the YARA-Scanner containers and Nginx:

```bash
    docker-compose up -d
```

4. Access the application

Once everything is up and running, you can access the YARA-Scanner application at http://localhost:8080/ in your web browser. To do a scan over a .exe, by using an app such as postman, send post request with "files[]" key.

## Application Components

The YARA-Scanner application consists of the following components:

1. **app/main.py**: Python Flask web application that handles file uploading and YARA scanning.

2. **requirements.txt**: File containing Python dependencies.

3. **Dockerfile**: Instructions for building the Docker image.

4. **docker-compose.yml**: Docker Compose configuration to define and manage the application services.

5. **nginx/conf.d/default.conf**: Nginx configuration for reverse proxy and load balancing.

## Load Balancing and Proxy

The `docker-compose.yml` file defines multiple instances of the YARA-Scanner application (`scanner_1`, `scanner_2`, `scanner_3`, and `scanner_4`). Nginx acts as a reverse proxy to distribute incoming requests among these instances.

The Nginx configuration `nginx/conf.d/default.conf` sets up the reverse proxy and load balancing:

```nginx
upstream scanner_backend {
    server scanner_1:8080;
    server scanner_2:8080;
    server scanner_3:8080;
    server scanner_4:8080;
    # Add more server entries for additional instances of the "scanner" service
}

server {
    listen 8080;

    location / {
        proxy_pass http://scanner_backend/upload;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

The `upstream` block defines the backend servers for load balancing. Requests to `/upload` are proxied to the `scanner_backend`, which consists of the YARA-Scanner instances.

This setup ensures that incoming requests are distributed among the available instances of the YARA-Scanner application, providing better scalability and fault tolerance.

Make sure to follow the instructions in the README.md to properly set up and run the YARA-Scanner application with Nginx load balancing and Docker.

## YARA Rules and Uploaded Files

YARA rules (with .yar extension) should be placed in the `static/yara-rules` directory within the application. However, If you plan to use it by docker and use another directory for rules be sure to mount bindings of the directory and change the configuration of volume accordingly in docker-compose.yml.

'''docker-compose
volumes: - YOUR/DIRECTORY/TO/YARA_RULES:/yara-app/static/yara-rules

During the scanning process, uploaded files are temporarily stored in the `static/uploads` directory.

## Scaling

To scale the YARA-Scanner application, you can adjust the number of instances in the `docker-compose.yml` file. By adding or removing `scanner` services, you can easily increase or decrease the number of YARA-Scanner instances.

# Details of main.py

YARA-Scanner is a web application that allows you to scan uploaded files against YARA rules to detect specific patterns or signatures in the files. YARA is a powerful pattern matching tool used for malware research and threat hunting.

## Python based prerequisites

If you plan to use app without Docker and load balancing before running the YARA-Scanner application, make sure you have the following installed:

- Python 3.x
- Flask (Python web framework)
- yara-python (Python bindings for YARA)
- python-magic (Python bindings for libmagic)

Installation can be done easily by using the following command after copying an instance of requirements.txt into your local:

```bash
    pip install -r requirements.txt
```

## Program Details

Once the application is running, you can access it at http://localhost:8080/ in your web browser.

### Uploading Files

To scan files, use the "/upload" endpoint with a POST request. The application supports uploading multiple files at once using the "files[]" key.

### YARA Rules

Place your YARA rules (with .yar extension) in the "static/yara-rules" directory before starting the application.

### File Uploads

Uploaded files will be saved in the "static/uploads" directory during the scanning process. Note that this application does not persistently store uploaded files.

### Thread Handling

The YARA-Scanner application uses threading to improve performance when scanning files against multiple YARA rules. You can set the `MAX_THREAD_NUMBER` variable in the "app.py" file to control the maximum number of threads used during scanning.

### Error Logging

Any errors that occur during YARA scanning will be logged in the "error.log" file.

## Note

- The application is intended for educational and informational purposes. Ensure you have proper authorization before scanning any files and do not use it to violate privacy or infringe upon the rights of others.
- For a production environment, additional security measures and configurations may be necessary.
