# Use a minimal, secure Java 21 JRE as the base image.
FROM eclipse-temurin:21-jre-jammy

# Install strace using the system's package manager
RUN apt-get update && apt-get install -y strace && rm -rf /var/lib/apt/lists/*

# Create a directory inside the container for our application.
WORKDIR /app

# Copy the target application JAR into the container.
COPY target/sandbox/application.jar /app/application.jar

# When the container starts, run the Java application *through strace*.
#
# -f                = Follow child processes (important for Java)
# -e trace=file     = Only trace system calls related to file access (open, read, write, stat, etc.)
# -e trace=network  = Only trace system calls related to networking (socket, connect, sendto, etc.)
#
ENTRYPOINT ["strace", "-f", "-e", "trace=file,network", "java", "-jar", "/app/application.jar"]