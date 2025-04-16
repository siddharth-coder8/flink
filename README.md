# Flink: Open Source Version Control System
![flink](https://github.com/user-attachments/assets/4246313a-9fd7-4f39-b170-a0febfc2e974)


Flink is a lightweight version control system that integrates with Firebase for remote repository storage. It supports repository initialization, file staging, commits, pushes, clones, and user profiles with usernames for privacy.

## Features

- Initialize public or private repositories
- Clone repositories by name or URL
- View user profiles with repository URLs
- Search and list public repositories
- Secure authentication with Firebase

## Prerequisites

- **Python 3.6+**
- A Firebase project with Authentication (Email/Password), Realtime Database, and Storage enabled
- `pip` for installing dependencies
- Git for cloning the repository

**Note**: Flink does not require a Firebase Admin SDK service account JSON file for client-side operations, as it uses the Firebase Web API for authentication and data access.

## Installation

### Option 1: Install via pip (Not Yet Available)

Flink will be available on PyPI in the future. Once published, you can install it globally with:

```bash
pip install flink-svector
```

### Option 2: Install from Source

1. **Clone the repository**:

   ```bash
   git clone https://github.com/siddharth-coder8/flink.git
   cd flink
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Set up Firebase configuration**:

     ```bash
     export FLINK_PROJECT_ID="your-project-id"
     export FLINK_API_KEY="your-api-key"
     export FLINK_DATABASE_URL="https://your-project-id-default-rtdb.api.svector.com"
     export FLINK_BUCKET_NAME="your-project-id.appspot.com"
     ```

     On Windows, use:

     ```cmd
     set FLINK_PROJECT_ID=your-project-id
     set FLINK_API_KEY=your-api-key
     set FLINK_DATABASE_URL=https://your-project-id-default-rtdb.api.svector.com
     set FLINK_BUCKET_NAME=your-project-id.appspot.com
     ```

4. **Deploy Firebase security rules**:

   - Copy the provided `database.rules.json` and `storage.rules.json` to your Firebase project.
   - Deploy via Firebase Console:
     - Realtime Database > Rules > Paste `database.rules.json` > Publish
     - Storage > Rules > Paste `storage.rules.json` > Publish
   - Or use the Firebase CLI:

     ```bash
     firebase deploy --only database,storage
     ```

## Usage

Below are common commands to get started with Flink. Run `flink --help` for a full list of commands.

- **Register a new user**:

  ```bash
  flink register user@example.com username
  ```

  Enter a password when prompted. Usernames must be unique and 3-50 alphanumeric characters or underscores.

- **Login**:

  ```bash
  flink login user@example.com
  ```

  Enter your password when prompted.

- **Initialize a repository**:

  ```bash
  flink init myrepo
  ```

  Choose `public` or `private` visibility. Creates a repository in `./myrepo`.

- **Add and commit files**:

  ```bash
  cd myrepo
  echo "Hello" > file.txt
  flink add .
  flink commit -m "Initial commit"
  ```

- **Push changes**:

  ```bash
  flink push
  ```

  Pushes to `https://api.flink.svector.co.in/username/myrepo` (replace with your domain if customized).

- **Clone a repository**:

  ```bash
  flink clone https://api.flink.svector.co.in/username/myrepo
  ```

  Or by name if public:

  ```bash
  flink clone myrepo
  ```

- **View profile**:

  ```bash
  flink profile
  ```

  Displays your username, email, and repositories with URLs.

- **List all public repositories**:

  ```bash
  flink all-repos
  ```

- **Search for repositories**:

  ```bash
  flink search myrepo
  ```

## Configuration

Flink stores user credentials securely in `~/.flink/credentials.json` with restricted permissions. To reset credentials:

```bash
rm -rf ~/.flink/credentials.json
```

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "Add your feature"`).
4. Push to your branch (`git push origin feature/your-feature`).
5. Open a pull request.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Support

For issues, feature requests, or questions:
- Open an issue on [GitHub](https://github.com/siddharth-coder8/flink/issues).
- Contact the maintainer at [team@svector.co.in]
