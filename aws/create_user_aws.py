import subprocess

def create_aws_user(username):
    try:
        result = subprocess.run(
            ["aws", "iam", "create-user", "--user-name", username],
            capture_output=True,
            text=True,
            check=True
        )
        print("User created successfully:")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print("Error creating user:")
        print(e.stderr)

if __name__ == "__main__":
    create_aws_user("test2")