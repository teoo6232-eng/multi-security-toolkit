# Copilot Instructions for multi-security-toolkit

## Project Overview

This is a multi-security-toolkit application written in Go. The project provides security tools and utilities for various security-related tasks.

## Technical Stack

- **Language**: Go (version 1.24.7 or compatible)
- **Module**: github.com/teoo6232-eng/multi-security-toolkit

## Project Structure

- `main.go`: Entry point for the application
- `go.mod`: Go module definition

## Development Guidelines

### Building the Project

```bash
go build -o multi-security-toolkit main.go
```

### Running the Application

```bash
go run main.go
```

### Code Style

- Follow standard Go conventions and idioms
- Use `gofmt` for code formatting
- Write clear, concise comments for exported functions and types
- Keep functions small and focused

### Best Practices

- Ensure all code is properly formatted with `gofmt`
- Add proper error handling for all operations
- Write unit tests for new functionality
- Follow Go's error handling patterns (avoid panic, prefer returning errors)
- Use meaningful variable and function names

## Security Considerations

As this is a security toolkit:
- Handle sensitive data with care
- Validate all inputs thoroughly
- Follow secure coding practices
- Consider security implications of all changes
- Document security-related functions clearly

## Future Development

The project is in early stages and will be expanded with additional security tools and features.
